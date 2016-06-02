package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/flynn/flynn/Godeps/_workspace/src/github.com/jackc/pgx"
	"github.com/flynn/flynn/Godeps/_workspace/src/golang.org/x/net/context"
	"github.com/flynn/flynn/pkg/postgres"
	"github.com/flynn/flynn/router/types"
)

var ErrNotFound = errors.New("router: route not found")
var ErrConflict = errors.New("router: duplicate route")
var ErrInvalid = errors.New("router: invalid route")

type DataStore interface {
	Add(route *router.Route) error
	Update(route *router.Route) error
	Get(id string) (*router.Route, error)
	List() ([]*router.Route, error)
	Remove(id string) error
	Sync(ctx context.Context, h SyncHandler, startc chan<- struct{}) error
	Ping() error
}

type DataStoreReader interface {
	Get(id string) (*router.Route, error)
	List() ([]*router.Route, error)
	Ping() error
}

type SyncHandler interface {
	Set(route *router.Route) error
	Remove(id string) error
	Current() map[string]struct{}
}

type pgDataStore struct {
	pgx *pgx.ConnPool

	routeType string
	tableName string
}

const (
	routeTypeHTTP              = "http"
	routeTypeTCP               = "tcp"
	tableNameHTTP              = "http_routes"
	tableNameTCP               = "tcp_routes"
	tableNameCertificates      = "certificates"
	tableNameRoutesCertificate = "routes_certificate"
)

// NewPostgresDataStore returns a DataStore that stores route information in a
// Postgres database. It uses pg_notify and a listener connection to watch for
// route changes.
func NewPostgresDataStore(routeType string, pgx *pgx.ConnPool) *pgDataStore {
	tableName := ""
	switch routeType {
	case routeTypeHTTP:
		tableName = tableNameHTTP
	case routeTypeTCP:
		tableName = tableNameTCP
	default:
		panic(fmt.Sprintf("unknown routeType: %q", routeType))
	}
	return &pgDataStore{
		pgx:       pgx,
		routeType: routeType,
		tableName: tableName,
	}
}

func (d *pgDataStore) Ping() error {
	_, err := d.pgx.Exec("SELECT 1")
	return err
}

const sqlAddRouteHTTP = `
INSERT INTO ` + tableNameHTTP + ` (parent_ref, service, leader, domain, sticky, path)
	VALUES ($1, $2, $3, $4, $5, $6)
	RETURNING id, created_at, updated_at`

const sqlAddRouteTCP = `
INSERT INTO ` + tableNameTCP + ` (parent_ref, service, leader, port)
	VALUES ($1, $2, $3, $4)
	RETURNING id, created_at, updated_at`

func (d *pgDataStore) Add(r *router.Route) (err error) {
	switch d.tableName {
	case tableNameHTTP:
		err = d.addHTTP(r)
	case tableNameTCP:
		err = d.addTCP(r)
	}
	r.Type = d.routeType
	if err != nil {
		if postgres.IsUniquenessError(err, "") {
			err = ErrConflict
		} else if postgres.IsPostgresCode(err, postgres.RaiseException) {
			err = ErrInvalid
		}
		return err
	}
	return nil
}

func (d *pgDataStore) addHTTP(r *router.Route) error {
	tx, err := d.pgx.Begin()
	if err != nil {
		return err
	}
	if err := tx.QueryRow(
		sqlAddRouteHTTP,
		r.ParentRef,
		r.Service,
		r.Leader,
		r.Domain,
		r.Sticky,
		r.Path,
	).Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt); err != nil {
		tx.Rollback()
		return err
	}
	if err := d.addRouteCertWithTx(tx, r); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (d *pgDataStore) addTCP(r *router.Route) error {
	return d.pgx.QueryRow(
		sqlAddRouteTCP,
		r.ParentRef,
		r.Service,
		r.Leader,
		r.Port,
	).Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt)
}

const sqlSelectCert = `
SELECT id, created_at, updated_at FROM ` + tableNameCertificates + `
	WHERE tls_cert_sha256 = $1 AND deleted_at IS NULL`

const sqlAddCert = `
INSERT INTO ` + tableNameCertificates + ` (tls_cert, tls_key, tls_cert_sha256)
	VALUES ($1, $2, $3)
	RETURNING id, created_at, updated_at
`

const sqlAddRouteCert = `
INSERT INTO ` + tableNameRoutesCertificate + ` (http_route_id, certificate_id)
	VALUES ($1, $2)
`

const sqlCleanupRouteCerts = `
DELETE FROM ` + tableNameRoutesCertificate + `
	WHERE http_route_id = $1`

func (d *pgDataStore) AddCert(c *router.RouteCert) error {
	tx, err := d.pgx.Begin()
	if err != nil {
		return err
	}
	if err := d.addCertWithTx(tx, c); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (d *pgDataStore) addCertWithTx(tx *pgx.Tx, c *router.RouteCert) error {
	tlsCertSHA256 := hex.EncodeToString(sha256.New().Sum([]byte(c.TLSCert)))
	if err := tx.QueryRow(sqlSelectCert, tlsCertSHA256).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt); err != nil {
		if err := tx.QueryRow(sqlAddCert, c.TLSCert, c.TLSKey, tlsCertSHA256).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return err
		}
	}
	for _, rid := range c.Routes {
		if _, err := tx.Exec(sqlCleanupRouteCerts, rid); err != nil {
			return err
		}
		if _, err := tx.Exec(sqlAddRouteCert, rid, c.ID); err != nil && !postgres.IsUniquenessError(err, "") {
			return err
		}
	}
	return nil
}

func (d *pgDataStore) addRouteCertWithTx(tx *pgx.Tx, r *router.Route) error {
	var cert *router.RouteCert
	if r.LegacyTLSCert != "" || r.LegacyTLSKey != "" {
		cert = &router.RouteCert{
			TLSCert: r.LegacyTLSCert,
			TLSKey:  r.LegacyTLSKey,
		}
	} else {
		cert = r.Certificate
	}
	if cert == nil {
		return nil
	}
	cert.Routes = []string{r.ID}
	if err := d.addCertWithTx(tx, cert); err != nil {
		return err
	}
	r.Certificate = &router.RouteCert{
		ID:        cert.ID,
		TLSCert:   cert.TLSCert,
		TLSKey:    cert.TLSKey,
		CreatedAt: cert.CreatedAt,
		UpdatedAt: cert.UpdatedAt,
	}
	return nil
}

const sqlUpdateRouteHTTP = `
UPDATE ` + tableNameHTTP + ` AS r
	SET parent_ref = $1, service = $2, leader = $3, sticky = $4, path = $5
	WHERE id = $6 AND domain = $7 AND deleted_at IS NULL
	RETURNING %s`

const sqlUpdateRouteTCP = `
UPDATE ` + tableNameTCP + ` SET parent_ref = $1, service = $2, leader = $3
	WHERE id = $4 AND port = $5 AND deleted_at IS NULL
	RETURNING %s`

func (d *pgDataStore) Update(r *router.Route) error {
	var err error

	switch d.tableName {
	case tableNameHTTP:
		err = d.updateHTTP(r)
	case tableNameTCP:
		err = d.updateTCP(r)
	}
	if err == pgx.ErrNoRows {
		return ErrNotFound
	}
	return err
}

func (d *pgDataStore) updateHTTP(r *router.Route) error {
	tx, err := d.pgx.Begin()
	if err != nil {
		return err
	}
	if err := d.scanRouteWithoutCert(r, d.pgx.QueryRow(
		fmt.Sprintf(sqlUpdateRouteHTTP, selectColumnsHTTP),
		r.ParentRef,
		r.Service,
		r.Leader,
		r.Sticky,
		r.Path,
		r.ID,
		r.Domain,
	)); err != nil {
		tx.Rollback()
		return err
	}
	if err := d.addRouteCertWithTx(tx, r); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (d *pgDataStore) updateTCP(r *router.Route) error {
	return d.scanRoute(r, d.pgx.QueryRow(
		fmt.Sprintf(sqlUpdateRouteTCP, d.columnNames()),
		r.ParentRef,
		r.Service,
		r.Leader,
		r.ID,
		r.Port,
	))
}

const sqlRemoveRoute = `UPDATE %s SET deleted_at = now() WHERE id = $1`

func (d *pgDataStore) Remove(id string) error {
	_, err := d.pgx.Exec(fmt.Sprintf(sqlRemoveRoute, d.tableName), id)
	if postgres.IsPostgresCode(err, postgres.RaiseException) {
		err = ErrInvalid
	}
	return err
}

const sqlGetHTTPRoute = `
SELECT %s FROM %s AS r
	LEFT OUTER JOIN %s AS rc ON r.id = rc.http_route_id
	LEFT OUTER JOIN %s AS c ON c.id = rc.certificate_id
	WHERE r.id = $1 AND r.deleted_at IS NULL`

const sqlGetTCPRoute = `SELECT %s FROM %s WHERE id = $1 AND deleted_at IS NULL`

func (d *pgDataStore) Get(id string) (*router.Route, error) {
	if id == "" {
		return nil, ErrNotFound
	}

	var query string
	switch d.tableName {
	case tableNameHTTP:
		query = fmt.Sprintf(sqlGetHTTPRoute, d.columnNames(), d.tableName, tableNameRoutesCertificate, tableNameCertificates)
	case tableNameTCP:
		query = fmt.Sprintf(sqlGetTCPRoute, d.columnNames(), d.tableName)
	}
	row := d.pgx.QueryRow(query, id)

	r := &router.Route{}
	err := d.scanRoute(r, row)
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	return r, nil
}

const sqlListHTTPRoutes = `
SELECT %s FROM %s AS r
	LEFT OUTER JOIN %s AS rc ON r.id = rc.http_route_id
	LEFT OUTER JOIN %s AS c ON c.id = rc.certificate_id
	WHERE r.deleted_at IS NULL`

const sqlListTCPRoutes = `SELECT %s FROM %s WHERE deleted_at IS NULL`

func (d *pgDataStore) List() ([]*router.Route, error) {
	var query string
	switch d.tableName {
	case tableNameHTTP:
		query = fmt.Sprintf(sqlListHTTPRoutes, d.columnNames(), d.tableName, tableNameRoutesCertificate, tableNameCertificates)
	case tableNameTCP:
		query = fmt.Sprintf(sqlListTCPRoutes, d.columnNames(), d.tableName)
	}
	rows, err := d.pgx.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	routes := []*router.Route{}
	for rows.Next() {
		r := &router.Route{}
		err := d.scanRoute(r, rows)
		if err != nil {
			return nil, err
		}

		r.Type = d.routeType
		routes = append(routes, r)
	}
	return routes, rows.Err()
}

func (d *pgDataStore) Sync(ctx context.Context, h SyncHandler, startc chan<- struct{}) error {
	ctx, cancel := context.WithCancel(ctx)

	idc, errc, err := d.startListener(ctx)
	if err != nil {
		return err
	}

	initialRoutes, err := d.List()
	if err != nil {
		cancel()
		return err
	}

	toRemove := h.Current()
	for _, route := range initialRoutes {
		if _, ok := toRemove[route.ID]; ok {
			delete(toRemove, route.ID)
		}
		if err := h.Set(route); err != nil {
			return err
		}
	}
	// send remove for any routes that are no longer in the database
	for id := range toRemove {
		if err := h.Remove(id); err != nil {
			return err
		}
	}
	close(startc)

	for {
		select {
		case id := <-idc:
			if err := d.handleUpdate(h, id); err != nil {
				cancel()
				return err
			}
		case err = <-errc:
			return err
		case <-ctx.Done():
			// wait for startListener to finish (it will either
			// close idc or send an error on errc)
			select {
			case <-idc:
			case <-errc:
			}
			return nil
		}
	}
}

func (d *pgDataStore) handleUpdate(h SyncHandler, id string) error {
	route, err := d.Get(id)
	if err == ErrNotFound {
		if err = h.Remove(id); err != nil && err != ErrNotFound {
			return err
		}
		return nil
	}
	if err != nil {
		return err
	}

	return h.Set(route)
}

func (d *pgDataStore) startListener(ctx context.Context) (<-chan string, <-chan error, error) {
	idc := make(chan string)
	errc := make(chan error)

	conn, err := d.pgx.Acquire()
	if err != nil {
		return nil, nil, err
	}
	if err = conn.Listen(d.tableName); err != nil {
		d.pgx.Release(conn)
		return nil, nil, err
	}

	go func() {
		defer unlistenAndRelease(d.pgx, conn, d.tableName)
		defer close(idc)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			notification, err := conn.WaitForNotification(time.Second)
			if err == pgx.ErrNotificationTimeout {
				continue
			}
			if err != nil {
				errc <- err
				return
			}

			idc <- notification.Payload
		}
	}()

	return idc, errc, nil
}

const (
	selectColumnsHTTP     = "r.id, r.parent_ref, r.service, r.leader, r.domain, r.sticky, r.path, r.created_at, r.updated_at"
	selectColumnsHTTPCert = "c.id, c.tls_cert, c.tls_key, c.created_at, c.updated_at"
	selectColumnsTCP      = "id, parent_ref, service, leader, port, created_at, updated_at"
)

func (d *pgDataStore) columnNames() string {
	switch d.routeType {
	case routeTypeHTTP:
		return selectColumnsHTTP + ", " + selectColumnsHTTPCert
	case routeTypeTCP:
		return selectColumnsTCP
	default:
		panic(fmt.Sprintf("unknown routeType: %q", d.routeType))
	}
}

type scannable interface {
	Scan(dest ...interface{}) (err error)
}

func (d *pgDataStore) scanRouteWithoutCert(route *router.Route, s scannable) error {
	route.Type = d.routeType
	switch d.tableName {
	case tableNameHTTP:
		return s.Scan(
			&route.ID,
			&route.ParentRef,
			&route.Service,
			&route.Leader,
			&route.Domain,
			&route.Sticky,
			&route.Path,
			&route.CreatedAt,
			&route.UpdatedAt,
		)
	case tableNameTCP:
		return s.Scan(
			&route.ID,
			&route.ParentRef,
			&route.Service,
			&route.Leader,
			&route.Port,
			&route.CreatedAt,
			&route.UpdatedAt,
		)
	}
	panic("unknown tableName: " + d.tableName)
}

func (d *pgDataStore) scanRoute(route *router.Route, s scannable) error {
	route.Type = d.routeType
	switch d.tableName {
	case tableNameHTTP:
		var certID, certTLSCert, certTLSKey *string
		var certCreatedAt, certUpdatedAt *time.Time
		if err := s.Scan(
			&route.ID,
			&route.ParentRef,
			&route.Service,
			&route.Leader,
			&route.Domain,
			&route.Sticky,
			&route.Path,
			&route.CreatedAt,
			&route.UpdatedAt,
			&certID,
			&certTLSCert,
			&certTLSKey,
			&certCreatedAt,
			&certUpdatedAt,
		); err != nil {
			return err
		}
		if certID != nil {
			route.Certificate = &router.RouteCert{
				ID:        *certID,
				TLSCert:   *certTLSCert,
				TLSKey:    *certTLSKey,
				CreatedAt: *certCreatedAt,
				UpdatedAt: *certUpdatedAt,
			}
		}
		return nil
	case tableNameTCP:
		return s.Scan(
			&route.ID,
			&route.ParentRef,
			&route.Service,
			&route.Leader,
			&route.Port,
			&route.CreatedAt,
			&route.UpdatedAt,
		)
	}
	panic("unknown tableName: " + d.tableName)
}

const sqlUnlisten = `UNLISTEN %s`

func unlistenAndRelease(pool *pgx.ConnPool, conn *pgx.Conn, channel string) {
	if _, err := conn.Exec(fmt.Sprintf(sqlUnlisten, channel)); err != nil {
		conn.Close()
	}
	pool.Release(conn)
}

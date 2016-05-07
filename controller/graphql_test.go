package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	. "github.com/flynn/flynn/Godeps/_workspace/src/github.com/flynn/go-check"
	"github.com/flynn/flynn/controller/client/v1"
	ct "github.com/flynn/flynn/controller/types"
	"github.com/flynn/flynn/pkg/random"
	"github.com/flynn/flynn/router/types"
	"github.com/graphql-go/handler"
)

func (s *S) TestGraphQL(c *C) {
	release := s.createTestRelease(c, &ct.Release{
		Meta: map[string]string{"biz": "baz"},
		Env:  map[string]string{"HELLO": "WORLD"},
		Processes: map[string]ct.ProcessType{
			"echo": ct.ProcessType{Cmd: []string{"echo"}},
		},
	})
	app := s.createTestApp(c, &ct.App{Meta: map[string]string{"foo": "bar"}})
	s.c.DeployAppRelease(app.ID, release.ID)
	s.createTestFormation(c, &ct.Formation{ReleaseID: release.ID, AppID: app.ID, Processes: map[string]int{
		"echo": 1,
	}})
	id := random.UUID()
	s.createTestJob(c, &ct.Job{UUID: id, AppID: app.ID, ReleaseID: release.ID, Type: "web", State: ct.JobStateStarting, Meta: map[string]string{"some": "info"}})

	resource, provider := s.provisionTestResource(c, "graphql-test", []string{app.ID})

	route0 := s.createTestRoute(c, app.ID, (&router.TCPRoute{Service: "first-service"}).ToRoute())
	s.createTestRoute(c, app.ID, (&router.HTTPRoute{Service: "second-service", Domain: "example.com"}).ToRoute())

	body := &handler.RequestOptions{
		Query: fmt.Sprintf(`{
			app(id: "%s") {
				name
				created_at
				updated_at
				current_release {
					id
				}
				releases {
					id
				}
				formations {
					created_at
					updated_at
				}
				deployments {
					id
					new_release {
						id
					}
				}
				jobs {
					id
					host_id
					uuid
					type
					meta
				}

				routes {
					type
					id
					parent_ref
					service
					leader
					created_at
					updated_at
					domain
					tls_cert
					tls_key
					sticky
					path
					port
				}
			}

			formation(app: "%s", release: "%s") {
				app {
					name
				}
				release {
					id
					artifacts {
						id
						type
					}
				}
			}

			artifact(id: "%s") {
				id
				type
			}

			release(id: "%s") {
				id
				artifacts {
					id
					type
				}
			}

			provider(id: "%s") {
				id
				name
				url
				created_at
				updated_at
				resources {
					id
					apps {
						name
					}
				}
			}

			resource(provider: "%s", id: "%s") {
				provider {
					name
				}
				external_id
				apps {
					name
				}
			}

			resources {
				id
			}

			route(app: "%s", id: "%s") {
				type
				id
				parent_ref
				domain
				port
				app {
					id
				}
			}
		}`, app.Name, app.ID, release.ID, release.ImageArtifactID(), release.ID, provider.ID, provider.ID, resource.ID, app.ID, route0.ID),
		Variables: map[string]interface{}{},
	}

	var out map[string]interface{}

	client := s.c.(*v1controller.Client)
	_, err := client.RawReq("POST", "/graphql", http.Header{"Content-Type": []string{"application/json"}}, body, &out)
	c.Assert(err, IsNil)
	data, err := json.MarshalIndent(out, "", "\t")
	c.Assert(err, IsNil)
	os.Stdout.Write(data)
	fmt.Println("")
}

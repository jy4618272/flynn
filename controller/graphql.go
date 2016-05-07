package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/flynn/flynn/Godeps/_workspace/src/golang.org/x/net/context"
	ct "github.com/flynn/flynn/controller/types"
	"github.com/flynn/flynn/host/types"
	"github.com/flynn/flynn/pkg/httphelper"
	"github.com/flynn/flynn/pkg/shutdown"
	"github.com/flynn/flynn/router/types"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	graphqlhandler "github.com/graphql-go/handler"
)

var graphqlSchema graphql.Schema

func newObjectType(name string) *graphql.Scalar {
	return graphql.NewScalar(graphql.ScalarConfig{
		Name: name,
		Serialize: func(value interface{}) interface{} {
			return value
		},
		ParseValue: func(value interface{}) interface{} {
			return value
		},
		ParseLiteral: func(valueAST ast.Value) interface{} {
			switch valueAST := valueAST.(type) {
			case *ast.ObjectValue:
				return valueAST.GetValue()
			}
			return nil
		},
	})
}

var (
	metaObjectType      = newObjectType("MetaObject")
	envObjectType       = newObjectType("EnvObject")
	processesObjectType = newObjectType("ProcessesObject")
	tagsObjectType      = newObjectType("TagsObject")
)

var graphqlTimeType = graphql.NewScalar(graphql.ScalarConfig{
	Name: "Time",
	Serialize: func(value interface{}) interface{} {
		if ts, ok := value.(*time.Time); ok {
			if data, err := ts.MarshalText(); err == nil {
				return string(data)
			}
		}
		if ts, ok := value.(time.Time); ok {
			if data, err := ts.MarshalText(); err == nil {
				return string(data)
			}
		}
		return nil
	},
	ParseValue: func(value interface{}) interface{} {
		if str, ok := value.(string); ok {
			var ts time.Time
			if err := ts.UnmarshalText([]byte(str)); err == nil {
				return &ts
			}
		}
		return nil
	},
	ParseLiteral: func(valueAST ast.Value) interface{} {
		switch valueAST := valueAST.(type) {
		case *ast.StringValue:
			return valueAST.GetValue()
		}
		return nil
	},
})

func wrapResolveFunc(fn func(*controllerAPI, graphql.ResolveParams) (interface{}, error)) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		api := p.Context.Value(apiContextKey).(*controllerAPI)
		return fn(api, p)
	}
}

func formationFieldResolveFunc(fn func(*controllerAPI, *ct.Formation) (interface{}, error)) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		api := p.Context.Value(apiContextKey).(*controllerAPI)
		if formation, ok := p.Source.(*ct.Formation); ok {
			return fn(api, formation)
		}
		return nil, nil
	}
}

func artifactFieldResolveFunc(fn func(*controllerAPI, *ct.Artifact) (interface{}, error)) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		api := p.Context.Value(apiContextKey).(*controllerAPI)
		if artifact, ok := p.Source.(*ct.Artifact); ok {
			return fn(api, artifact)
		}
		return nil, nil
	}
}

func releaseFieldResolveFunc(fn func(*controllerAPI, *ct.Release) (interface{}, error)) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		api := p.Context.Value(apiContextKey).(*controllerAPI)
		if release, ok := p.Source.(*ct.Release); ok {
			return fn(api, release)
		}
		return nil, nil
	}
}

func appFieldResolveFunc(fn func(*controllerAPI, *ct.App) (interface{}, error)) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		api := p.Context.Value(apiContextKey).(*controllerAPI)
		if app, ok := p.Source.(*ct.App); ok {
			return fn(api, app)
		}
		return nil, nil
	}
}

func deploymentFieldResolveFunc(fn func(*controllerAPI, *ct.Deployment) (interface{}, error)) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		api := p.Context.Value(apiContextKey).(*controllerAPI)
		if deployment, ok := p.Source.(*ct.Deployment); ok {
			return fn(api, deployment)
		}
		return nil, nil
	}
}

func jobFieldResolveFunc(fn func(*controllerAPI, *ct.Job) (interface{}, error)) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		api := p.Context.Value(apiContextKey).(*controllerAPI)
		if job, ok := p.Source.(*ct.Job); ok {
			return fn(api, job)
		}
		return nil, nil
	}
}

func providerFieldResolveFunc(fn func(*controllerAPI, *ct.Provider) (interface{}, error)) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		api := p.Context.Value(apiContextKey).(*controllerAPI)
		if provider, ok := p.Source.(*ct.Provider); ok {
			return fn(api, provider)
		}
		return nil, nil
	}
}

func resourceFieldResolveFunc(fn func(*controllerAPI, *ct.Resource) (interface{}, error)) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		api := p.Context.Value(apiContextKey).(*controllerAPI)
		if resource, ok := p.Source.(*ct.Resource); ok {
			return fn(api, resource)
		}
		return nil, nil
	}
}

func routeFieldResolveFunc(fn func(*controllerAPI, *router.Route) (interface{}, error)) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		api := p.Context.Value(apiContextKey).(*controllerAPI)
		if route, ok := p.Source.(*router.Route); ok {
			return fn(api, route)
		}
		return nil, nil
	}
}

func listArtifacts(api *controllerAPI, artifactIDs []string) ([]*ct.Artifact, error) {
	artifactMap, err := api.artifactRepo.ListIDs(artifactIDs...)
	if err != nil {
		return nil, err
	}
	artifacts := make([]*ct.Artifact, len(artifactMap))
	i := 0
	for _, a := range artifactMap {
		artifacts[i] = a
		i++
	}
	return artifacts, nil
}

func init() {
	formationObject := graphql.NewObject(graphql.ObjectConfig{
		Name: "Formation",
		Fields: graphql.Fields{
			"processes": &graphql.Field{
				Type:        processesObjectType,
				Description: "Processes",
				Resolve: formationFieldResolveFunc(func(_ *controllerAPI, f *ct.Formation) (interface{}, error) {
					return f.Processes, nil
				}),
			},
			"tags": &graphql.Field{
				Type:        tagsObjectType,
				Description: "Tags",
				Resolve: formationFieldResolveFunc(func(_ *controllerAPI, f *ct.Formation) (interface{}, error) {
					return f.Tags, nil
				}),
			},
			"created_at": &graphql.Field{
				Type:        graphqlTimeType,
				Description: "Time formation was created",
				Resolve: formationFieldResolveFunc(func(_ *controllerAPI, f *ct.Formation) (interface{}, error) {
					return f.CreatedAt, nil
				}),
			},
			"updated_at": &graphql.Field{
				Type:        graphqlTimeType,
				Description: "Time formation was last updated",
				Resolve: formationFieldResolveFunc(func(_ *controllerAPI, f *ct.Formation) (interface{}, error) {
					return f.UpdatedAt, nil
				}),
			},
		},
	})

	artifactObject := graphql.NewObject(graphql.ObjectConfig{
		Name: "Artifact",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type:        graphql.String,
				Description: "UUID of artifact",
				Resolve: artifactFieldResolveFunc(func(_ *controllerAPI, artifact *ct.Artifact) (interface{}, error) {
					return artifact.ID, nil
				}),
			},
			"type": &graphql.Field{
				Type: graphql.NewEnum(graphql.EnumConfig{
					Name:        "ArtifactType",
					Description: "Type of artifact",
					Values: graphql.EnumValueConfigMap{
						string(host.ArtifactTypeDocker): &graphql.EnumValueConfig{
							Value:       host.ArtifactTypeDocker,
							Description: "Docker image",
						},
						string(host.ArtifactTypeFile): &graphql.EnumValueConfig{
							Value:       host.ArtifactTypeFile,
							Description: "Generic file",
						},
					},
				}),
				Resolve: artifactFieldResolveFunc(func(_ *controllerAPI, artifact *ct.Artifact) (interface{}, error) {
					return artifact.Type, nil
				}),
			},
			"uri": &graphql.Field{
				Type:        graphql.String,
				Description: "URI of artifact",
				Resolve: artifactFieldResolveFunc(func(_ *controllerAPI, artifact *ct.Artifact) (interface{}, error) {
					return artifact.URI, nil
				}),
			},
			"meta": &graphql.Field{
				Type:        metaObjectType,
				Description: "Meta for artifact",
				Resolve: artifactFieldResolveFunc(func(_ *controllerAPI, artifact *ct.Artifact) (interface{}, error) {
					return artifact.Meta, nil
				}),
			},
			"created_at": &graphql.Field{
				Type:        metaObjectType,
				Description: "Time artifact was created",
				Resolve: artifactFieldResolveFunc(func(_ *controllerAPI, artifact *ct.Artifact) (interface{}, error) {
					return artifact.CreatedAt, nil
				}),
			},
		},
	})

	releaseObject := graphql.NewObject(graphql.ObjectConfig{
		Name: "Release",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type:        metaObjectType,
				Description: "UUID of release",
				Resolve: releaseFieldResolveFunc(func(_ *controllerAPI, release *ct.Release) (interface{}, error) {
					return release.ID, nil
				}),
			},
			"artifacts": &graphql.Field{
				Type:        graphql.NewList(artifactObject),
				Description: "Artifacts for release",
				Resolve: releaseFieldResolveFunc(func(api *controllerAPI, release *ct.Release) (interface{}, error) {
					artifactIDs := make([]string, 0, len(release.ArtifactIDs)+1)
					if release.LegacyArtifactID != "" {
						artifactIDs = append(artifactIDs, release.LegacyArtifactID)
					}
					for _, id := range release.ArtifactIDs {
						artifactIDs = append(artifactIDs, id)
					}
					return listArtifacts(api, artifactIDs)
				}),
			},
			"image_artifact": &graphql.Field{
				Type:        artifactObject,
				Description: "Image artifact for release",
				Resolve: releaseFieldResolveFunc(func(api *controllerAPI, release *ct.Release) (interface{}, error) {
					return api.artifactRepo.Get(release.ImageArtifactID())
				}),
			},
			"file_artifacts": &graphql.Field{
				Type:        graphql.NewList(artifactObject),
				Description: "File artifacts for release",
				Resolve: releaseFieldResolveFunc(func(api *controllerAPI, release *ct.Release) (interface{}, error) {
					return listArtifacts(api, release.FileArtifactIDs())
				}),
			},
			"env": &graphql.Field{
				Type:        metaObjectType,
				Description: "Env for release",
				Resolve: releaseFieldResolveFunc(func(_ *controllerAPI, release *ct.Release) (interface{}, error) {
					return release.Env, nil
				}),
			},
			"meta": &graphql.Field{
				Type:        metaObjectType,
				Description: "Metadata for release",
				Resolve: releaseFieldResolveFunc(func(_ *controllerAPI, release *ct.Release) (interface{}, error) {
					return release.Meta, nil
				}),
			},
			"created_at": &graphql.Field{
				Type:        graphqlTimeType,
				Description: "Time formation was created",
				Resolve: releaseFieldResolveFunc(func(_ *controllerAPI, release *ct.Release) (interface{}, error) {
					return release.CreatedAt, nil
				}),
			},
		},
	})

	appObject := graphql.NewObject(graphql.ObjectConfig{
		Name: "App",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type:        graphql.NewNonNull(graphql.String),
				Description: "UUID of app",
				Resolve: appFieldResolveFunc(func(_ *controllerAPI, app *ct.App) (interface{}, error) {
					return app.ID, nil
				}),
			},
			"name": &graphql.Field{
				Type:        graphql.NewNonNull(graphql.String),
				Description: "Name of app",
				Resolve: appFieldResolveFunc(func(_ *controllerAPI, app *ct.App) (interface{}, error) {
					return app.Name, nil
				}),
			},
			"meta": &graphql.Field{
				Type:        metaObjectType,
				Description: "Metadata for app",
				Resolve: appFieldResolveFunc(func(_ *controllerAPI, app *ct.App) (interface{}, error) {
					return app.Meta, nil
				}),
			},
			"strategy": &graphql.Field{
				Type:        graphql.NewNonNull(graphql.String),
				Description: "Deployment strategy for app",
				Resolve: appFieldResolveFunc(func(_ *controllerAPI, app *ct.App) (interface{}, error) {
					return app.Strategy, nil
				}),
			},
			"deploy_timeout": &graphql.Field{
				Type:        graphql.Int,
				Description: "Deploy timeout in seconds",
				Resolve: appFieldResolveFunc(func(_ *controllerAPI, app *ct.App) (interface{}, error) {
					return app.DeployTimeout, nil
				}),
			},
			"created_at": &graphql.Field{
				Type:        graphqlTimeType,
				Description: "Time app was created",
				Resolve: appFieldResolveFunc(func(_ *controllerAPI, app *ct.App) (interface{}, error) {
					return app.CreatedAt, nil
				}),
			},
			"updated_at": &graphql.Field{
				Type:        graphqlTimeType,
				Description: "Time app was last updated",
				Resolve: appFieldResolveFunc(func(_ *controllerAPI, app *ct.App) (interface{}, error) {
					return app.UpdatedAt, nil
				}),
			},
			"current_release": &graphql.Field{
				Type:        releaseObject,
				Description: "Current release for app",
				Resolve: appFieldResolveFunc(func(api *controllerAPI, app *ct.App) (interface{}, error) {
					return api.appRepo.GetRelease(app.ID)
				}),
			},
			"releases": &graphql.Field{
				Type:        graphql.NewList(releaseObject),
				Description: "Releases for app",
				Resolve: appFieldResolveFunc(func(api *controllerAPI, app *ct.App) (interface{}, error) {
					return api.releaseRepo.AppList(app.ID)
				}),
			},
			"formations": &graphql.Field{
				Type:        graphql.NewList(formationObject),
				Description: "Formations for app",
				Resolve: appFieldResolveFunc(func(api *controllerAPI, app *ct.App) (interface{}, error) {
					return api.formationRepo.List(app.ID)
				}),
			},
		},
	})

	deploymentObject := graphql.NewObject(graphql.ObjectConfig{
		Name: "Deployment",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type:        graphql.NewNonNull(graphql.String),
				Description: "UUID of app",
				Resolve: deploymentFieldResolveFunc(func(_ *controllerAPI, d *ct.Deployment) (interface{}, error) {
					return d.ID, nil
				}),
			},
			"app": &graphql.Field{
				Type:        appObject,
				Description: "App deployment belongs to",
				Resolve: deploymentFieldResolveFunc(func(api *controllerAPI, d *ct.Deployment) (interface{}, error) {
					return api.appRepo.Get(d.AppID)
				}),
			},
			"old_release": &graphql.Field{
				Type:        releaseObject,
				Description: "Old release",
				Resolve: deploymentFieldResolveFunc(func(api *controllerAPI, d *ct.Deployment) (interface{}, error) {
					return api.releaseRepo.Get(d.OldReleaseID)
				}),
			},
			"new_release": &graphql.Field{
				Type:        releaseObject,
				Description: "New release",
				Resolve: deploymentFieldResolveFunc(func(api *controllerAPI, d *ct.Deployment) (interface{}, error) {
					return api.releaseRepo.Get(d.NewReleaseID)
				}),
			},
			"strategy": &graphql.Field{
				Type:        graphql.String,
				Description: "Deployment stategy",
				Resolve: deploymentFieldResolveFunc(func(_ *controllerAPI, d *ct.Deployment) (interface{}, error) {
					return d.Strategy, nil
				}),
			},
			"status": &graphql.Field{
				Type:        graphql.String,
				Description: "Status of deployment",
				Resolve: deploymentFieldResolveFunc(func(_ *controllerAPI, d *ct.Deployment) (interface{}, error) {
					return d.Status, nil
				}),
			},
			"deploy_timeout": &graphql.Field{
				Type:        graphql.Int,
				Description: "Time in seconds before the deployment times out",
				Resolve: deploymentFieldResolveFunc(func(_ *controllerAPI, d *ct.Deployment) (interface{}, error) {
					return d.Status, nil
				}),
			},
			"processes": &graphql.Field{
				Type:        processesObjectType,
				Description: "Processes included in deployment",
				Resolve: deploymentFieldResolveFunc(func(_ *controllerAPI, d *ct.Deployment) (interface{}, error) {
					return d.Processes, nil
				}),
			},
			"created_at": &graphql.Field{
				Type:        graphqlTimeType,
				Description: "Time deployment was created",
				Resolve: deploymentFieldResolveFunc(func(_ *controllerAPI, d *ct.Deployment) (interface{}, error) {
					return d.CreatedAt, nil
				}),
			},
			"finished_at": &graphql.Field{
				Type:        graphqlTimeType,
				Description: "Time deployment finished",
				Resolve: deploymentFieldResolveFunc(func(_ *controllerAPI, d *ct.Deployment) (interface{}, error) {
					return d.FinishedAt, nil
				}),
			},
		},
	})

	jobObject := graphql.NewObject(graphql.ObjectConfig{
		Name: "Job",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type:        graphql.String,
				Description: "Full cluster ID of job",
				Resolve: jobFieldResolveFunc(func(_ *controllerAPI, job *ct.Job) (interface{}, error) {
					return job.ID, nil
				}),
			},
			"uuid": &graphql.Field{
				Type:        graphql.NewNonNull(graphql.String),
				Description: "UUID of job",
				Resolve: jobFieldResolveFunc(func(_ *controllerAPI, job *ct.Job) (interface{}, error) {
					return job.UUID, nil
				}),
			},
			"host_id": &graphql.Field{
				Type:        graphql.String,
				Description: "Host ID of job",
				Resolve: jobFieldResolveFunc(func(_ *controllerAPI, job *ct.Job) (interface{}, error) {
					return job.HostID, nil
				}),
			},
			"app": &graphql.Field{
				Type:        appObject,
				Description: "App job belongs to",
				Resolve: jobFieldResolveFunc(func(api *controllerAPI, job *ct.Job) (interface{}, error) {
					return api.appRepo.Get(job.AppID)
				}),
			},
			"release": &graphql.Field{
				Type:        releaseObject,
				Description: "Release job belongs to",
				Resolve: jobFieldResolveFunc(func(api *controllerAPI, job *ct.Job) (interface{}, error) {
					return api.releaseRepo.Get(job.ReleaseID)
				}),
			},
			"type": &graphql.Field{
				Type:        graphql.String,
				Description: "Type of job",
				Resolve: jobFieldResolveFunc(func(_ *controllerAPI, job *ct.Job) (interface{}, error) {
					return job.Type, nil
				}),
			},
			"state": &graphql.Field{
				Type: graphql.NewEnum(graphql.EnumConfig{
					Name:        "JobState",
					Description: "State of job",
					Values: graphql.EnumValueConfigMap{
						string(ct.JobStatePending): &graphql.EnumValueConfig{
							Value: ct.JobStatePending,
						},
						string(ct.JobStateStarting): &graphql.EnumValueConfig{
							Value: ct.JobStateStarting,
						},
						string(ct.JobStateUp): &graphql.EnumValueConfig{
							Value: ct.JobStateUp,
						},
						string(ct.JobStateStopping): &graphql.EnumValueConfig{
							Value: ct.JobStateStopping,
						},
						string(ct.JobStateDown): &graphql.EnumValueConfig{
							Value: ct.JobStateDown,
						},
						string(ct.JobStateCrashed): &graphql.EnumValueConfig{
							Value:             ct.JobStateCrashed,
							DeprecationReason: "No longer a valid job state",
						},
						string(ct.JobStateFailed): &graphql.EnumValueConfig{
							Value:             ct.JobStateFailed,
							DeprecationReason: "No longer a valid job state",
						},
					},
				}),
				Description: "Type of job",
				Resolve: jobFieldResolveFunc(func(_ *controllerAPI, job *ct.Job) (interface{}, error) {
					return job.Type, nil
				}),
			},
			"cmd": &graphql.Field{
				Type:        graphql.NewList(graphql.String),
				Description: "Cmd of job",
				Resolve: jobFieldResolveFunc(func(_ *controllerAPI, job *ct.Job) (interface{}, error) {
					return job.Cmd, nil
				}),
			},
			"meta": &graphql.Field{
				Type:        metaObjectType,
				Description: "Cmd of job",
				Resolve: jobFieldResolveFunc(func(_ *controllerAPI, job *ct.Job) (interface{}, error) {
					return job.Meta, nil
				}),
			},
			"exit_status": &graphql.Field{
				Type:        graphql.Int,
				Description: "Exit status of job",
				Resolve: jobFieldResolveFunc(func(_ *controllerAPI, job *ct.Job) (interface{}, error) {
					return job.ExitStatus, nil
				}),
			},
			"host_error": &graphql.Field{
				Type:        graphql.String,
				Description: "Host error",
				Resolve: jobFieldResolveFunc(func(_ *controllerAPI, job *ct.Job) (interface{}, error) {
					return job.HostError, nil
				}),
			},
			"run_at": &graphql.Field{
				Type:        graphqlTimeType,
				Description: "Time job should run at",
				Resolve: jobFieldResolveFunc(func(_ *controllerAPI, job *ct.Job) (interface{}, error) {
					return job.RunAt, nil
				}),
			},
			"restarts": &graphql.Field{
				Type:        graphql.Int,
				Description: "Number of times job has restarted",
				Resolve: jobFieldResolveFunc(func(_ *controllerAPI, job *ct.Job) (interface{}, error) {
					return job.Restarts, nil
				}),
			},
			"created_at": &graphql.Field{
				Type:        graphqlTimeType,
				Description: "Time job was created",
				Resolve: jobFieldResolveFunc(func(_ *controllerAPI, job *ct.Job) (interface{}, error) {
					return job.CreatedAt, nil
				}),
			},
			"updated_at": &graphql.Field{
				Type:        graphqlTimeType,
				Description: "Time job was last updated",
				Resolve: jobFieldResolveFunc(func(_ *controllerAPI, job *ct.Job) (interface{}, error) {
					return job.UpdatedAt, nil
				}),
			},
		},
	})

	providerObject := graphql.NewObject(graphql.ObjectConfig{
		Name: "Provider",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type:        graphql.NewNonNull(graphql.String),
				Description: "UUID of provider",
				Resolve: providerFieldResolveFunc(func(_ *controllerAPI, p *ct.Provider) (interface{}, error) {
					return p.ID, nil
				}),
			},
			"url": &graphql.Field{
				Type:        graphql.NewNonNull(graphql.String),
				Description: "URL of provider",
				Resolve: providerFieldResolveFunc(func(_ *controllerAPI, p *ct.Provider) (interface{}, error) {
					return p.URL, nil
				}),
			},
			"name": &graphql.Field{
				Type:        graphql.NewNonNull(graphql.String),
				Description: "Name of provider",
				Resolve: providerFieldResolveFunc(func(_ *controllerAPI, p *ct.Provider) (interface{}, error) {
					return p.Name, nil
				}),
			},
			"created_at": &graphql.Field{
				Type:        graphqlTimeType,
				Description: "Time provider was created",
				Resolve: providerFieldResolveFunc(func(_ *controllerAPI, p *ct.Provider) (interface{}, error) {
					return p.CreatedAt, nil
				}),
			},
			"updated_at": &graphql.Field{
				Type:        graphqlTimeType,
				Description: "Time provider was last updated",
				Resolve: providerFieldResolveFunc(func(_ *controllerAPI, p *ct.Provider) (interface{}, error) {
					return p.UpdatedAt, nil
				}),
			},
		},
	})

	resourceObject := graphql.NewObject(graphql.ObjectConfig{
		Name: "Resource",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type:        graphql.NewNonNull(graphql.String),
				Description: "UUID of resource",
				Resolve: resourceFieldResolveFunc(func(_ *controllerAPI, r *ct.Resource) (interface{}, error) {
					return r.ID, nil
				}),
			},
			"provider": &graphql.Field{
				Type:        providerObject,
				Description: "Provider of resource",
				Resolve: resourceFieldResolveFunc(func(api *controllerAPI, r *ct.Resource) (interface{}, error) {
					return api.providerRepo.Get(r.ProviderID)
				}),
			},
			"external_id": &graphql.Field{
				Type:        graphql.String,
				Description: "External ID of resource",
				Resolve: resourceFieldResolveFunc(func(_ *controllerAPI, r *ct.Resource) (interface{}, error) {
					return r.ExternalID, nil
				}),
			},
			"env": &graphql.Field{
				Type:        envObjectType,
				Description: "Env of resource",
				Resolve: resourceFieldResolveFunc(func(_ *controllerAPI, r *ct.Resource) (interface{}, error) {
					return r.Env, nil
				}),
			},
			"apps": &graphql.Field{
				Type:        graphql.NewList(appObject),
				Description: "Apps associated with resource",
				Resolve: resourceFieldResolveFunc(func(api *controllerAPI, r *ct.Resource) (interface{}, error) {
					return api.appRepo.ListIDs(r.Apps...)
				}),
			},
			"created_at": &graphql.Field{
				Type:        graphqlTimeType,
				Description: "Time resource was created at",
				Resolve: resourceFieldResolveFunc(func(_ *controllerAPI, r *ct.Resource) (interface{}, error) {
					return r.CreatedAt, nil
				}),
			},
		},
	})

	routeObject := graphql.NewObject(graphql.ObjectConfig{
		Name: "Route",
		Fields: graphql.Fields{
			"type": &graphql.Field{
				Type:        graphql.NewNonNull(graphql.String),
				Description: "Type of route",
				Resolve: routeFieldResolveFunc(func(_ *controllerAPI, r *router.Route) (interface{}, error) {
					return r.Type, nil
				}),
			},
			"id": &graphql.Field{
				Type:        graphql.NewNonNull(graphql.String),
				Description: "UUID of route",
				Resolve: routeFieldResolveFunc(func(_ *controllerAPI, r *router.Route) (interface{}, error) {
					return r.ID, nil
				}),
			},
			"parent_ref": &graphql.Field{
				Type:        graphql.String,
				Description: "External opaque ID",
				Resolve: routeFieldResolveFunc(func(_ *controllerAPI, r *router.Route) (interface{}, error) {
					return r.ParentRef, nil
				}),
			},
			"service": &graphql.Field{
				Type:        graphql.String,
				Description: "ID of the service",
				Resolve: routeFieldResolveFunc(func(_ *controllerAPI, r *router.Route) (interface{}, error) {
					return r.Service, nil
				}),
			},
			"leader": &graphql.Field{
				Type:        graphql.Boolean,
				Description: "Route traffic to the only to the leader when true",
				Resolve: routeFieldResolveFunc(func(_ *controllerAPI, r *router.Route) (interface{}, error) {
					return r.Leader, nil
				}),
			},
			"created_at": &graphql.Field{
				Type:        graphqlTimeType,
				Description: "Time route was created",
				Resolve: routeFieldResolveFunc(func(_ *controllerAPI, r *router.Route) (interface{}, error) {
					return r.CreatedAt, nil
				}),
			},
			"updated_at": &graphql.Field{
				Type:        graphqlTimeType,
				Description: "Time route was last updated",
				Resolve: routeFieldResolveFunc(func(_ *controllerAPI, r *router.Route) (interface{}, error) {
					return r.UpdatedAt, nil
				}),
			},
			"domain": &graphql.Field{
				Type:        graphql.String,
				Description: "Domain name of route (HTTP routes only)",
				Resolve: routeFieldResolveFunc(func(_ *controllerAPI, r *router.Route) (interface{}, error) {
					return r.Domain, nil
				}),
			},
			"tls_cert": &graphql.Field{
				Type:        graphql.String,
				Description: "TLS public certificate of route",
				Resolve: routeFieldResolveFunc(func(_ *controllerAPI, r *router.Route) (interface{}, error) {
					return r.TLSCert, nil
				}),
			},
			"tls_key": &graphql.Field{
				Type:        graphql.String,
				Description: "TLS private key of route",
				Resolve: routeFieldResolveFunc(func(_ *controllerAPI, r *router.Route) (interface{}, error) {
					return r.TLSKey, nil
				}),
			},
			"sticky": &graphql.Field{
				Type:        graphql.Boolean,
				Description: "Use sticky sessions for route when true (HTTP routes only)",
				Resolve: routeFieldResolveFunc(func(_ *controllerAPI, r *router.Route) (interface{}, error) {
					return r.Sticky, nil
				}),
			},
			"path": &graphql.Field{
				Type:        graphql.String,
				Description: "Prefix to route to this service.",
				Resolve: routeFieldResolveFunc(func(_ *controllerAPI, r *router.Route) (interface{}, error) {
					return r.Path, nil
				}),
			},
			"port": &graphql.Field{
				Type:        graphql.Int,
				Description: "TPC port to listen on (TCP routes only)",
				Resolve: routeFieldResolveFunc(func(_ *controllerAPI, r *router.Route) (interface{}, error) {
					return r.Port, nil
				}),
			},
			"app": &graphql.Field{
				Type:        appObject,
				Description: "App route belongs to",
				Resolve: routeFieldResolveFunc(func(api *controllerAPI, r *router.Route) (interface{}, error) {
					if strings.HasPrefix(r.ParentRef, ct.RouteParentRefPrefix) {
						appID := strings.TrimPrefix(r.ParentRef, ct.RouteParentRefPrefix)
						return api.appRepo.Get(appID)
					}
					return nil, nil
				}),
			},
		},
	})

	formationObject.AddFieldConfig("app", &graphql.Field{
		Type:        appObject,
		Description: "App formation belongs to",
		Resolve: formationFieldResolveFunc(func(api *controllerAPI, f *ct.Formation) (interface{}, error) {
			return api.appRepo.Get(f.AppID)
		}),
	})
	formationObject.AddFieldConfig("release", &graphql.Field{
		Type:        releaseObject,
		Description: "Release formation belongs to",
		Resolve: formationFieldResolveFunc(func(api *controllerAPI, f *ct.Formation) (interface{}, error) {
			return api.releaseRepo.Get(f.ReleaseID)
		}),
	})

	appObject.AddFieldConfig("deployments", &graphql.Field{
		Type:        graphql.NewList(deploymentObject),
		Description: "Deployments for app",
		Resolve: appFieldResolveFunc(func(api *controllerAPI, app *ct.App) (interface{}, error) {
			return api.deploymentRepo.List(app.ID)
		}),
	})
	appObject.AddFieldConfig("jobs", &graphql.Field{
		Type:        graphql.NewList(jobObject),
		Description: "Jobs for app",
		Resolve: appFieldResolveFunc(func(api *controllerAPI, app *ct.App) (interface{}, error) {
			return api.jobRepo.List(app.ID)
		}),
	})
	appObject.AddFieldConfig("routes", &graphql.Field{
		Type:        graphql.NewList(routeObject),
		Description: "Routes for app",
		Resolve: appFieldResolveFunc(func(api *controllerAPI, app *ct.App) (interface{}, error) {
			return api.routerc.ListRoutes(routeParentRef(app.ID))
		}),
	})

	providerObject.AddFieldConfig("resources", &graphql.Field{
		Type:        graphql.NewList(resourceObject),
		Description: "Resources for provider",
		Resolve: providerFieldResolveFunc(func(api *controllerAPI, p *ct.Provider) (interface{}, error) {
			return api.resourceRepo.ProviderList(p.ID)
		}),
	})

	var err error
	graphqlSchema, err = graphql.NewSchema(graphql.SchemaConfig{
		Query: graphql.NewObject(graphql.ObjectConfig{
			Name: "RootQuery",
			Fields: graphql.Fields{
				"app": &graphql.Field{
					Type: appObject,
					Args: graphql.FieldConfigArgument{
						"id": &graphql.ArgumentConfig{
							Description: "UUID or name of app",
							Type:        graphql.NewNonNull(graphql.String),
						},
					},
					Resolve: wrapResolveFunc(func(api *controllerAPI, p graphql.ResolveParams) (interface{}, error) {
						return api.appRepo.Get(p.Args["id"].(string))
					}),
				},
				"artifact": &graphql.Field{
					Type: artifactObject,
					Args: graphql.FieldConfigArgument{
						"id": &graphql.ArgumentConfig{
							Description: "UUID of artifact",
							Type:        graphql.NewNonNull(graphql.String),
						},
					},
					Resolve: wrapResolveFunc(func(api *controllerAPI, p graphql.ResolveParams) (interface{}, error) {
						return api.artifactRepo.Get(p.Args["id"].(string))
					}),
				},
				"release": &graphql.Field{
					Type: releaseObject,
					Args: graphql.FieldConfigArgument{
						"id": &graphql.ArgumentConfig{
							Description: "UUID of release",
							Type:        graphql.NewNonNull(graphql.String),
						},
					},
					Resolve: wrapResolveFunc(func(api *controllerAPI, p graphql.ResolveParams) (interface{}, error) {
						return api.releaseRepo.Get(p.Args["id"].(string))
					}),
				},
				"formation": &graphql.Field{
					Type: formationObject,
					Args: graphql.FieldConfigArgument{
						"app": &graphql.ArgumentConfig{
							Type: graphql.NewNonNull(graphql.String),
						},
						"release": &graphql.ArgumentConfig{
							Type: graphql.NewNonNull(graphql.String),
						},
					},
					Resolve: wrapResolveFunc(func(api *controllerAPI, p graphql.ResolveParams) (interface{}, error) {
						return api.formationRepo.Get(p.Args["app"].(string), p.Args["release"].(string))
					}),
				},
				"deployment": &graphql.Field{
					Type: deploymentObject,
					Args: graphql.FieldConfigArgument{
						"id": &graphql.ArgumentConfig{
							Description: "UUID of deployment",
							Type:        graphql.NewNonNull(graphql.String),
						},
					},
					Resolve: wrapResolveFunc(func(api *controllerAPI, p graphql.ResolveParams) (interface{}, error) {
						return api.deploymentRepo.Get(p.Args["id"].(string))
					}),
				},
				"job": &graphql.Field{
					Type: jobObject,
					Args: graphql.FieldConfigArgument{
						"uuid": &graphql.ArgumentConfig{
							Description: "UUID of job",
							Type:        graphql.NewNonNull(graphql.String),
						},
					},
					Resolve: wrapResolveFunc(func(api *controllerAPI, p graphql.ResolveParams) (interface{}, error) {
						return api.jobRepo.Get(p.Args["id"].(string))
					}),
				},
				"provider": &graphql.Field{
					Type: providerObject,
					Args: graphql.FieldConfigArgument{
						"id": &graphql.ArgumentConfig{
							Description: "UUID of provider",
							Type:        graphql.NewNonNull(graphql.String),
						},
					},
					Resolve: wrapResolveFunc(func(api *controllerAPI, p graphql.ResolveParams) (interface{}, error) {
						return api.providerRepo.Get(p.Args["id"].(string))
					}),
				},
				"resource": &graphql.Field{
					Type: resourceObject,
					Args: graphql.FieldConfigArgument{
						"provider": &graphql.ArgumentConfig{
							Description: "UUID of provider",
							Type:        graphql.NewNonNull(graphql.String),
						},
						"id": &graphql.ArgumentConfig{
							Description: "UUID of resource",
							Type:        graphql.NewNonNull(graphql.String),
						},
					},
					Resolve: wrapResolveFunc(func(api *controllerAPI, p graphql.ResolveParams) (interface{}, error) {
						_, err := api.providerRepo.Get(p.Args["provider"].(string))
						if err != nil {
							return nil, err
						}
						return api.resourceRepo.Get(p.Args["id"].(string))
					}),
				},
				"resources": &graphql.Field{
					Type: graphql.NewList(resourceObject),
					Resolve: wrapResolveFunc(func(api *controllerAPI, p graphql.ResolveParams) (interface{}, error) {
						return api.resourceRepo.List()
					}),
				},
				"route": &graphql.Field{
					Type: routeObject,
					Args: graphql.FieldConfigArgument{
						"app": &graphql.ArgumentConfig{
							Description: "UUID of app",
							Type:        graphql.NewNonNull(graphql.String),
						},
						"id": &graphql.ArgumentConfig{
							Description: "UUID of route",
							Type:        graphql.NewNonNull(graphql.String),
						},
					},
					Resolve: wrapResolveFunc(func(api *controllerAPI, p graphql.ResolveParams) (interface{}, error) {
						parts := strings.SplitN(p.Args["id"].(string), "/", 2)
						return api.getRoute(p.Args["app"].(string), parts[0], parts[1])
					}),
				},
				"event": nil,
			},
		}),
		Mutation: nil,
	})
	if err != nil {
		shutdown.Fatal(err)
	}
}

const (
	apiContextKey = "controllerAPI"
)

func contextWithAPI(api *controllerAPI, ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, apiContextKey, api)
	return ctx
}

func (api *controllerAPI) GraphQLHandler() httphelper.HandlerFunc {
	h := graphqlhandler.New(&graphqlhandler.Config{
		Schema: &graphqlSchema,
		Pretty: false,
	})
	return func(ctx context.Context, w http.ResponseWriter, req *http.Request) {
		h.ContextHandler(contextWithAPI(api, ctx), w, req)
	}
}

UPDATE {{ .Ident "resource_history" }}
SET
  {{ .Ident "group" }} = {{ .Arg .Group }},
  {{ .Ident "resource" }} = {{ .Arg .Resource }},
  {{ .Ident "namespace" }} = {{ .Arg .Namespace }},
  {{ .Ident "name" }} = {{ .Arg .Name }},
  {{ .Ident "action" }} = {{ .Arg .Action }},
  {{ .Ident "folder" }} = {{ .Arg .Folder }},
  {{ .Ident "previous_resource_version" }} = {{ .Arg .PreviousRV }},
  {{ .Ident "generation" }} = {{ .Arg .Generation }}
WHERE {{ .Ident "guid" }} = {{ .Arg .GUID }};

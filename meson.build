project('curl-test', 'c')

deps = []
deps += dependency('gio-2.0')
deps += dependency('gio-unix-2.0')
deps += dependency('glib-2.0')
# deps += dependency('libsodium')

main_sources = files([
  'main.c',
  'http_request.c'

])


executable('glib-http',
  sources: main_sources,
  dependencies : deps
  )

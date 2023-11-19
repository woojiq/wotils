project('ping', 'c', version: '0.1')

inc = include_directories('include')

ping_src = []
raw_src = ['main.c', 'args.c', 'icmp.c']
foreach src : raw_src
  ping_src += files(join_paths('src', src))
endforeach

executable('ping', ping_src, include_directories: inc, install: true)

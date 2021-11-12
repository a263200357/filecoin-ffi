module github.com/a263200357/filecoin-ffi

go 1.13

require (
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	github.com/xlab/c-for-go v0.0.0-20201112171043-ea6dce5809cb
	golang.org/x/tools v0.0.0-20201112185108-eeaa07dd7696 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	modernc.org/golex v1.0.1 // indirect
)

replace github.com/a263200357/filecoin-ffi/generated => ./genereted

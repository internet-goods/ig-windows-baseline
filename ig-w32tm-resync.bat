echo make time sync even if far out of date, useful for laptop with broken battery
w32tm /resync /force
w32tm /stripchart /computer:pool.ntp.org /dataonly /samples:5

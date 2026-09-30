package security

import "time"

// timeNow 封装 time.Now 以便测试时替换。
var timeNow = time.Now

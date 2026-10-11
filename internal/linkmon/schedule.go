package linkmon

import "time"

// nightlyDue — пора ли ночной замер скорости: сейчас в течение часа после
// hh:mm местного времени и сегодня замера ещё не было.
func nightlyDue(now, last time.Time, hh, mm int) bool {
	at := time.Date(now.Year(), now.Month(), now.Day(), hh, mm, 0, 0, now.Location())
	return !now.Before(at) && now.Before(at.Add(time.Hour)) && last.Before(at)
}

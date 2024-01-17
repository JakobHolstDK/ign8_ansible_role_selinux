curl -X POST -H "Content-Type: application/json" -d '{
  "hostname": "dashdb01",
  "event": "example-event",
  "date": "2023-12-01",
  "time": "00:00:05",
  "serial_num": 27182,
  "event_kind": "bpf-program",
  "session": null,
  "subj_prime": null,
  "subj_sec": null,
  "subj_kind": "system",
  "action": "loaded-bpf-program",
  "result": null,
  "obj_prime": "2093",
  "obj_sec": null,
  "obj_kind": "process",
  "how": null
}' http://localhost:8000/selinux/selinux_event/

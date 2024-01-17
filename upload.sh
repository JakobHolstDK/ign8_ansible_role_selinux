curl -X POST -H "Content-Type: application/json" -d '{
  "hostname": "example2.com",
  "status": "Enforcing",
  "mount": "/",
  "rootdir": "/root",
  "policyname": "targeted",
  "current_mode": "permissive",
  "configured_mode": "enforcing",
  "mslstatus": "disabled",
  "memprotect": "enabled",
  "maxkernel": "4.18.0",
  "total": "256",
  "success": "10",
  "failed": "2",
  "sealerts": "9"
  }' http://localhost:8000/selinux/upload/

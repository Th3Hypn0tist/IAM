<?php

declare(strict_types=1);
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IAM registration</title>
<style>
body{font-family:system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem;background:#111;color:#eee}
form{display:grid;gap:1rem}label{display:grid;gap:.35rem}input,button{font:inherit;padding:.7rem}
button{cursor:pointer}.status{min-height:1.5rem}small{color:#aaa}
</style>
</head>
<body>
<h1>Register</h1>
<p>IAM light registration. An invite code is required.</p>
<form id="register">
<label>Invite code <input name="invite_code" required autocomplete="off"></label>
<label>Username <input name="username" required autocomplete="username" maxlength="128"></label>
<label>Email <input name="email" type="email" autocomplete="email"></label>
<label>Password <input name="password" type="password" required autocomplete="new-password" minlength="8"></label>
<label>Repeat password <input name="repeat" type="password" required autocomplete="new-password" minlength="8"></label>
<button type="submit">Register</button>
<div class="status" id="status" role="status"></div>
</form>
<script>
const form=document.getElementById('register');
const status=document.getElementById('status');
form.addEventListener('submit',async(event)=>{
  event.preventDefault();
  status.textContent='';
  const data=new FormData(form);
  if(data.get('password')!==data.get('repeat')){
    status.textContent='Passwords do not match.';
    return;
  }
  const payload={
    invite_code:data.get('invite_code'),
    username:data.get('username'),
    email:data.get('email'),
    password:data.get('password')
  };
  try{
    const response=await fetch('../api/register.php',{
      method:'POST',
      headers:{'Content-Type':'application/json','Accept':'application/json'},
      credentials:'same-origin',
      body:JSON.stringify(payload)
    });
    const body=await response.json();
    if(!response.ok||body.ok!==true) throw new Error(body.error||'Registration failed');
    form.reset();
    status.textContent='Registration complete. You are signed in.';
  }catch(error){
    status.textContent=error instanceof Error?error.message:'Registration failed';
  }
});
</script>
</body>
</html>

import { useRef, useState } from 'react'
import { Link, BrowserRouter, Routes, Route, Outlet } from "react-router-dom";
import './App.css'
import axios from "axios"
import {Transaction, SystemProgram, PublicKey, LAMPORTS_PER_SOL, Connection} from "@solana/web3.js"

const connection = new Connection("https://devnet.helius-rpc.com/?api-key=0da89612-6136-410f-8718-66f8e4b35d33");

// const fromPubkey = new PublicKey("DnDm1Aii8TAacpraLuv2HYqJHxGSCN4RdcRTe5Q1KjF7");

function App() {

   //function sendCustomTokens() {}
  //function buyMemeCoin() {}

  return (
    <>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route path="/api/vi/signup" element={<SignUp />} />
          <Route path="/api/vi/signin" element={<SignIn />} />
          <Route path="/api/vi/txn/sign" element={<SendSolana />} />
          <Route path="/api/vi/txn" element={<GetStatus />} />
          <Route path="*" element={<ErrorPage />} />
        </Route>
      </Routes>  
    </BrowserRouter>  
    </>
  )
}

function Layout() {
  return <div>
      Layout Bonk Bot Header
      <br/> <br/> <br/> <br/> 
      <Link to="/api/vi/signup">Sign Up</Link>
       |||
      <Link to="/api/vi/signin">Sign In</Link> 
      |||
      <Link to="/api/vi/txn/sign">Send Solana</Link> 
      |||
      <Link to="/api/vi/txn/">Get Status</Link>     
    <Outlet/>
    <br/> <br/> <br/> <br/> <br/> <br/>
    <br/> <br/> <br/> <br/> <br/>
    Layout Footer || Contact Us
    
  </div>
}

function SignUp() {
  
  const nameRef = useRef();
  const passRef = useRef();
  const [pubKey, setPubKey] = useState();
  const [isVisible, setIsVisible] = useState(false);

  async function createKey() {

    const pubkey = await axios.post("http://localhost:3000/api/vi/signup",{
      username: nameRef.current.value,
      password: passRef.current.value
    });
    console.log("Public Key is: " + pubkey.data.message);
    setPubKey(pubkey.data.message);
    setIsVisible(true);
    localStorage.removeItem('jwt');
  }

  return <div>
    <br/> <br/>
    Sign Up to create new Keypair
    <br/> <br/>
    <input ref={nameRef} type='text' placeholder='UserName'></input>
    <input ref={passRef} type='text' placeholder='Password'></input>
    <br/> <br/>
    <button onClick={createKey}>Submit</button>
    <br /> <br />
    { isVisible && <div> {nameRef.current.value} Public Key: {pubKey} </div>}
  </div>
}

function SignIn() {

  const nameRef = useRef();
  const passRef = useRef();
  const [jwtToken, setJwtToken] = useState(null);
  const [isVisible, setIsVisible] = useState(false);

  async function verifyUser() {

    const jtoken = await axios.post("http://localhost:3000/api/vi/signin",{
      username: nameRef.current.value, 
      password: passRef.current.value
    });

    console.log("Jwt is:" + JSON.stringify(jtoken.data.token));
    setJwtToken(jtoken.data.token); 
    setIsVisible(true);
    localStorage.setItem('jwt', jtoken.data.token);
  } 

  return <div>
    <br/> <br/>
      Sign In to Bonk Bot
      <br/> <br/>
    <input ref={nameRef} type='text' placeholder='UserName'></input>
    <input ref={passRef} type='text' placeholder='Password'></input>
    <br/> <br/>
    <button onClick={verifyUser}>Submit</button>
    <br /> <br />
    { isVisible && <div> {nameRef.current.value} JWT {jwtToken} </div>}
  </div>
}

function SendSolana() {

  const [hash, setHash] = useState({});
  const [isVisible, setIsVisible] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const sAddressRef = useRef();
  const amountRef = useRef();
  const rAddressRef = useRef();

  // jwt of user local storage need to check ?
  // Get JWT from localStorage
  const getStoredToken = () => {
    return localStorage.getItem('jwt');
  };

  // Add JWT to request headers
  const setAuthHeader = () => {
    const token = getStoredToken();
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    } else {
      delete axios.defaults.headers.common['Authorization'];
    }
  };

  if(error) {
    return <div>
      Error...encounteredddd !!!
    </div>
  } 

  async function sendSol(){

      setLoading(true);

      try {
      const sPubKey = new PublicKey(sAddressRef.current.value);
      const amt = amountRef.current.value * LAMPORTS_PER_SOL;
      const rPubKey = new PublicKey(rAddressRef.current.value);

      const ix = SystemProgram.transfer({
      fromPubkey: sPubKey,
      toPubkey: rPubKey,
      lamports: amt
      });

      const tx = new Transaction().add(ix);
      // convert the tx into bytes for it to be transfer over wire like json, html, xml
      // Transaction is a class, a class cannot be sent, receiving end be written in python, doesnt know class writen in JS

      const latestBlockHash = await connection.getLatestBlockhash();
      tx.recentBlockhash = latestBlockHash.blockhash;
      tx.feePayer = sPubKey;

      const serialTx = tx.serialize({
        requireAllSignatures: false,
        verifySignatures: false
      });
      // If you run at this moment, error comes that  Buffer is not there
      // @solana/web3.js is meant for the BE/Server
      // if you want to use in FE, install node-polyfills
      setAuthHeader();
    
      const resp = await axios.post("http://localhost:3000/api/vi/txn/sign",{
        message: serialTx,
        retry: false
        // ,headers: {    'Authorization': `Bearer ${token}`}
      });
      setHash(resp);
      setIsVisible(true);
      } 
      catch (err) {
        if (error.response?.status === 401) {
          // Token is invalid or expired
          localStorage.removeItem('jwt');
          // setAuthError('Session expired. Please login again.');
        }
        setError("There was error encountered " + error);
      } finally {
        setLoading(false);
      }
    }

  return <div>
      <br/> <br/>
      Enter the below details
      <br/> <br/>
      <input ref={sAddressRef} type='text' placeholder='Sender Address'></input>
      <input ref={amountRef} type='text' placeholder='Amount'></input>
      <input ref={rAddressRef} type='text' placeholder='Receiver Address'></input>
      <br/> <br/>
      <button onClick={sendSol}>Submit</button>
      {isVisible && <div>
        {JSON.stringify(hash.data.message)}
      </div>}
  </div>
}

function GetStatus() {

  const [hash, setHash] = useState({});
  const [error, setError] = useState();
  const [isVisible, setIsVisible] = useState(false);

  const txSignRef = useRef();

  async function getSignature() {
    try {  
      const resp = await axios.post("http://localhost:3000/api/vi/txn/",{
        message: txSignRef.current.value
      });
      
      setHash(resp.data.message);
      setIsVisible(true);
      console.log("After Axois getSign " + resp.data.message);
    } 
    catch (err) {
      setError("There was error encountered " + error);
      setIsVisible(true);
    }
  }

  return <div>
      <br/> <br/>
      Get Status of your Transaction
      <br/> <br/>
      <input ref={txSignRef} type='text' placeholder='Transaction Signature'></input>
      <br/> <br/>
      <button onClick={getSignature}>Status</button>
      {isVisible ? <div>
        {hash}
      </div> : <div> {error} </div>}
      <br/> <br/>
  </div>
}

function ErrorPage() {
  return <div>
    Error 404
  </div>
}

export default App

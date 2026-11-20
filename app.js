const express = require('express');
const app = express()
const port = 3201
const routes = require("./routes/routerIndex")
const cors = require('cors');
app.use(cors());

app.use(express.json());

app.use('/api', routes);
app.get('/', (req, res) => { return res.send('Hello World!') });


app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
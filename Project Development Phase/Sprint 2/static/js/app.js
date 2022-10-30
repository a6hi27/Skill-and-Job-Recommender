var req = unirest("GET", "https://www.universal-tutorial.com/api/getaccesstoken");

req.headers({
    "Accept": "application/json",
    "api-token": "d6OnmrD9Lydl9-d2C14o0cDnqv2M4SO5qhJu1zklHwxUde9A4m85xnuV5nd3QksvEew",
    "user-email": "2k19cse001@kiot.ac.in"
});
document.addEventListener("DOMContentLoaded", () => {

    const selectDrop = document.querySelector('#countries');
    let countries = document.getElementById("countries")
    let countryName = countries.value;
    let finalURL = `https://restcountries.com/v3.1/all`;
    console.log(finalURL);
    fetch(finalURL)
        .then((response) => response.json())
        .then((data) => {
            let output = "";

            data.forEach(country => {
                output += `<option value="${country.name.common}">${country.name.common}</option>`
            });

            //   console.log(Object.keys(data[0].currencies)[0]);
            //   console.log(data[0].currencies[Object.keys(data[0].currencies)].name);
            //   console.log(
            //     Object.values(data[0].languages).toString().split(",").join(", ")
            //   );
            selectDrop.innerHTML = output
        })
        .catch(() => {
            if (countryName.length == 0) {
                result.innerHTML = `<h3>The input field cannot be empty</h3>`;
            } else {
                result.innerHTML = `<h3>Please enter a valid country name.</h3>`;
            }
        });
});

/* global artifacts */
require('dotenv').config({ path: '../.env' })
const MATICSmashnado = artifacts.require('MATICSmashnado')
const Verifier = artifacts.require('Verifier')
const hasherContract = artifacts.require('Hasher')


module.exports = function(deployer, network, accounts) {
  return deployer.then(async () => {
    const { MERKLE_TREE_HEIGHT, ETH_AMOUNT_T } = process.env
    const verifier = await Verifier.deployed()
    const hasherInstance = await hasherContract.deployed()
    await MATICSmashnado.link(hasherContract, hasherInstance.address)
    const smashnado = await deployer.deploy(MATICSmashnado, verifier.address, ETH_AMOUNT_T, MERKLE_TREE_HEIGHT, accounts[0])
    console.log('MATICSmashnado\'s address ', smashnado.address)
  })
}

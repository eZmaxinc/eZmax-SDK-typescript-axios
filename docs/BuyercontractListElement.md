# BuyercontractListElement

A Buyercontract List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiBuyercontractID** | **number** | The unique ID of the Buyercontract | [default to undefined]
**fkiInscriptiontypeID** | **number** | The unique ID of the Inscriptiontype | [default to undefined]
**sInscriptiontypeNameX** | **string** | The name of the Inscriptiontype in the language of the requester | [default to undefined]
**eBuyercontractStep** | [**FieldEBuyercontractStep**](FieldEBuyercontractStep.md) |  | [default to undefined]
**dBuyercontractMinimumprice** | **string** | The minimumprice of the Buyercontract | [default to undefined]
**dBuyercontractMaximumprice** | **string** | The maximumprice of the Buyercontract | [default to undefined]
**eBuyercontractType** | [**FieldEBuyercontractType**](FieldEBuyercontractType.md) |  | [default to undefined]
**dtBuyercontractDate** | **string** | The date of the Buyercontract | [default to undefined]
**dtBuyercontractExpirationdate** | **string** | The expirationdate of the Buyercontract | [optional] [default to undefined]
**bBuyercontractIsactive** | **boolean** | Whether the buyercontract is active or not | [default to undefined]
**sBuyercontractBrokers** | **string** | The brokers\&#39; name of the Buyercontract | [default to undefined]
**sBuyercontractBuyers** | **string** | The buyers\&#39; name of the Buyercontract | [default to undefined]

## Example

```typescript
import { BuyercontractListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: BuyercontractListElement = {
    pkiBuyercontractID,
    fkiInscriptiontypeID,
    sInscriptiontypeNameX,
    eBuyercontractStep,
    dBuyercontractMinimumprice,
    dBuyercontractMaximumprice,
    eBuyercontractType,
    dtBuyercontractDate,
    dtBuyercontractExpirationdate,
    bBuyercontractIsactive,
    sBuyercontractBrokers,
    sBuyercontractBuyers,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

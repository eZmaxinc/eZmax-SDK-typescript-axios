# BuyercontractResponse

A Buyercontract Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiBuyercontractID** | **number** | The unique ID of the Buyercontract | [default to undefined]
**fkiInscriptiontypeID** | **number** | The unique ID of the Inscriptiontype | [default to undefined]
**eBuyercontractStep** | [**FieldEBuyercontractStep**](FieldEBuyercontractStep.md) |  | [default to undefined]
**dBuyercontractMinimumprice** | **string** | The minimum price of the Buyercontract | [default to undefined]
**dBuyercontractMaximumprice** | **string** | The maximum price of the Buyercontract | [default to undefined]
**eBuyercontractType** | [**FieldEBuyercontractType**](FieldEBuyercontractType.md) |  | [default to undefined]
**sBuyercontractContract** | **string** | The number of the Buyercontract | [optional] [default to undefined]
**dtBuyercontractDate** | **string** | The date of the Buyercontract | [default to undefined]
**dtBuyercontractExpirationdate** | **string** | The expiration date of the Buyercontract | [optional] [default to undefined]
**dBuyercontractRemuneration** | **string** | The remuneration of the Buyercontract | [optional] [default to undefined]
**eBuyercontractRemunerationtype** | [**FieldEBuyercontractRemunerationtype**](FieldEBuyercontractRemunerationtype.md) |  | [optional] [default to undefined]
**bBuyercontractLitigation** | **boolean** | Whether if it\&#39;s an litigation | [optional] [default to undefined]
**bBuyercontractIsactive** | **boolean** | Whether the buyercontract is active or not | [default to undefined]

## Example

```typescript
import { BuyercontractResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: BuyercontractResponse = {
    pkiBuyercontractID,
    fkiInscriptiontypeID,
    eBuyercontractStep,
    dBuyercontractMinimumprice,
    dBuyercontractMaximumprice,
    eBuyercontractType,
    sBuyercontractContract,
    dtBuyercontractDate,
    dtBuyercontractExpirationdate,
    dBuyercontractRemuneration,
    eBuyercontractRemunerationtype,
    bBuyercontractLitigation,
    bBuyercontractIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

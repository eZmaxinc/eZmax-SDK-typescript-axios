# PurchaseListElement

A Purchase List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiPurchaseID** | **number** | The unique ID of the Purchase | [default to undefined]
**fkiFranchiseofficeID** | **number** | The unique ID of the Franchisereoffice | [optional] [default to undefined]
**fkiSupplierID** | **number** | The unique ID of the Supplier. | [optional] [default to undefined]
**fkiPeriodID** | **number** | The unique ID of the Period | [default to undefined]
**sPurchaseBillnumber** | **string** | The Billnumber of the Purchase | [default to undefined]
**dtPurchaseDate** | **string** | The Date of the Purchase | [default to undefined]
**dtPurchasePaydate** | **string** | The Paydate of the Purchase | [default to undefined]
**dPurchaseTotal** | **string** | The Total of the Purchase | [default to undefined]
**bPurchaseIsfinanced** | **boolean** | Whether if it\&#39;s an isfinanced | [default to undefined]
**bPurchaseIspaid** | **boolean** | Whether if it\&#39;s an ispaid | [default to undefined]
**sFranchiseagenceName** | **string** | The name of the Franchiseagence | [optional] [default to undefined]
**iFranchiseofficeCode** | **string** | The code of the Franchiseoffice | [optional] [default to undefined]
**sSupplierName** | **string** | The name of the Supplier | [optional] [default to undefined]

## Example

```typescript
import { PurchaseListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: PurchaseListElement = {
    pkiPurchaseID,
    fkiFranchiseofficeID,
    fkiSupplierID,
    fkiPeriodID,
    sPurchaseBillnumber,
    dtPurchaseDate,
    dtPurchasePaydate,
    dPurchaseTotal,
    bPurchaseIsfinanced,
    bPurchaseIspaid,
    sFranchiseagenceName,
    iFranchiseofficeCode,
    sSupplierName,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

# SupplierListElement

A Supplier List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiSupplierID** | **number** | The unique ID of the Supplier. | [default to undefined]
**fkiPaymentmethodID** | **number** | The unique ID of the Paymentmethod | [optional] [default to undefined]
**sSupplierName** | **string** | The name of the Supplier | [default to undefined]
**sSupplierCode** | **string** | The code of the Supplier | [default to undefined]
**sSupplierAccount** | **string** | The account of the Supplier | [default to undefined]
**bSupplierIsactive** | **boolean** | Whether the supplier is active or not | [default to undefined]
**sPhoneE164** | **string** | A phone number in E.164 Format | [optional] [default to undefined]
**sEmailAddress** | **string** | The email address. | [optional] [default to undefined]
**sAddressCivic** | **string** | The Civic number. | [optional] [default to undefined]
**sAddressStreet** | **string** | The Street Name | [optional] [default to undefined]
**sAddressSuite** | **string** | The Suite or appartment number | [optional] [default to undefined]
**sAddressCity** | **string** | The City name | [optional] [default to undefined]
**sAddressZip** | **string** | The Postal/Zip Code  The value must be entered without spaces | [optional] [default to undefined]
**sProvinceNameX** | **string** | The name of the Province in the language of the requester | [optional] [default to undefined]
**sCountryNameX** | **string** | The name of the Country in the language of the requester | [optional] [default to undefined]
**sPaymentmethodDescriptionX** | **string** | The description of the Paymentmethod in the language of the requester | [optional] [default to undefined]
**sElectronicfundstransferbankaccountTransit** | **string** | The transit of the Electronicfundstransferbankaccount | [optional] [default to undefined]
**sElectronicfundstransferbankaccountInstitution** | **string** | The institution of the Electronicfundstransferbankaccount | [optional] [default to undefined]
**sElectronicfundstransferbankaccountAccount** | **string** | The account of the Electronicfundstransferbankaccount | [optional] [default to undefined]
**sGlaccountcontainerLongcode** | **string** | The Code for the Glaccountcontainer | [default to undefined]
**sGlaccountcontainerLongdescriptionX** | **string** | The Description for the Glaccountcontainer in the language of the requester | [default to undefined]

## Example

```typescript
import { SupplierListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: SupplierListElement = {
    pkiSupplierID,
    fkiPaymentmethodID,
    sSupplierName,
    sSupplierCode,
    sSupplierAccount,
    bSupplierIsactive,
    sPhoneE164,
    sEmailAddress,
    sAddressCivic,
    sAddressStreet,
    sAddressSuite,
    sAddressCity,
    sAddressZip,
    sProvinceNameX,
    sCountryNameX,
    sPaymentmethodDescriptionX,
    sElectronicfundstransferbankaccountTransit,
    sElectronicfundstransferbankaccountInstitution,
    sElectronicfundstransferbankaccountAccount,
    sGlaccountcontainerLongcode,
    sGlaccountcontainerLongdescriptionX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

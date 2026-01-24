# CommonResponseErrorWrongFranchiseoffice

Error Message when a Franchisebroker is not in this Franchiseoffice.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sErrorMessage** | **string** | The message giving details about the error | [default to undefined]
**eErrorCode** | [**FieldEErrorCode**](FieldEErrorCode.md) |  | [default to undefined]
**a_sErrorMessagedetail** | **Array&lt;string&gt;** | More error message detail | [optional] [default to undefined]
**fkiFranchiseagenceID** | **number** | The unique ID of the Franchiseagence | [default to undefined]
**sFranchiseagenceName** | **string** | The name of the Franchiseagence | [default to undefined]
**fkiFranchiseofficeID** | **number** | The unique ID of the Franchisereoffice | [default to undefined]
**iFranchiseofficeCode** | **string** | The code of the Franchiseoffice | [default to undefined]

## Example

```typescript
import { CommonResponseErrorWrongFranchiseoffice } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommonResponseErrorWrongFranchiseoffice = {
    sErrorMessage,
    eErrorCode,
    a_sErrorMessagedetail,
    fkiFranchiseagenceID,
    sFranchiseagenceName,
    fkiFranchiseofficeID,
    iFranchiseofficeCode,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

# CustomerAutocompleteElementResponse

A Customer AutocompleteElement Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiCustomerID** | **number** | The unique ID of the Customer. | [default to undefined]
**fkiDepartmentID** | **number** | The unique ID of the Department | [default to undefined]
**sCustomerName** | **string** | The name of the Customer | [default to undefined]
**sCustomerCode** | **string** | The code of the Customer | [default to undefined]
**bCustomerIsactive** | **boolean** | Whether the customer is active or not | [default to undefined]

## Example

```typescript
import { CustomerAutocompleteElementResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomerAutocompleteElementResponse = {
    pkiCustomerID,
    fkiDepartmentID,
    sCustomerName,
    sCustomerCode,
    bCustomerIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

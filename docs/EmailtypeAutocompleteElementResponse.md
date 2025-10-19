# EmailtypeAutocompleteElementResponse

A Emailtype AutocompleteElement Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEmailtypeID** | **number** | The unique ID of the Emailtype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home| | [default to undefined]
**sEmailtypeNameX** | **string** | The name of the Emailtype in the language of the requester | [default to undefined]
**bEmailtypeIsactive** | **boolean** | Whether the Emailtype is active or not | [default to undefined]

## Example

```typescript
import { EmailtypeAutocompleteElementResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EmailtypeAutocompleteElementResponse = {
    pkiEmailtypeID,
    sEmailtypeNameX,
    bEmailtypeIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

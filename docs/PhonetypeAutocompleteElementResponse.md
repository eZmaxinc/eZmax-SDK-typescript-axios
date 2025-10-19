# PhonetypeAutocompleteElementResponse

A Phonetype AutocompleteElement Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiPhonetypeID** | **number** | The unique ID of the Phonetype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home| |3|Mobile| |4|Fax| |5|Pager| |6|Toll Free| | [default to undefined]
**sPhonetypeNameX** | **string** | The name of the Phonetype in the language of the requester | [default to undefined]
**bPhonetypeIsactive** | **boolean** | Whether the Phonetype is active or not | [default to undefined]

## Example

```typescript
import { PhonetypeAutocompleteElementResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: PhonetypeAutocompleteElementResponse = {
    pkiPhonetypeID,
    sPhonetypeNameX,
    bPhonetypeIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

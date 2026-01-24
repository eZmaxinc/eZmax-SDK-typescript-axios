# EzsigntemplatedocumentGetWordsPositionsV1Request

Request for POST /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/getWordsPositions

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**eGet** | **string** | Specify if you want to retrieve *All* words or specific *Words* from the document. If you specify *Words*, you must send the list of words to search for in *a_sWord*. | [default to undefined]
**bWordCaseSensitive** | **boolean** | IF *true*, words will be searched case-sensitive and results will be returned case-sensitive. IF *false*, words will be searched case-insensitive and results will be returned case-insensitive. | [default to undefined]
**a_sWord** | **Array&lt;string&gt;** | Array of words to find in the document | [optional] [default to undefined]

## Example

```typescript
import { EzsigntemplatedocumentGetWordsPositionsV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatedocumentGetWordsPositionsV1Request = {
    eGet,
    bWordCaseSensitive,
    a_sWord,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

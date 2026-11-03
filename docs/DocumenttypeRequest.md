# DocumenttypeRequest

A Documenttype Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiDocumenttypeID** | **number** | The unique ID of the Documenttype | [optional] [default to undefined]
**objDocumenttypeName** | [**MultilingualDocumenttypeName**](MultilingualDocumenttypeName.md) |  | [default to undefined]
**eDocumenttypeStep** | [**ComputedEDocumenttypeStep**](ComputedEDocumenttypeStep.md) |  | [default to undefined]
**sDocumenttypeDefaultfilename** | **string** | The defaultfilename of the Documenttype | [default to undefined]
**bDocumenttypeShowagent** | **boolean** | Whether if it\&#39;s an showagent | [default to undefined]
**bDocumenttypeIsactive** | **boolean** | Whether the documenttype is active or not | [default to undefined]
**bDocumenttypeIsrequired** | **boolean** | Whether if it\&#39;s an isrequired | [default to undefined]
**bDocumenttypeSale** | **boolean** | Whether if it\&#39;s an sale | [default to undefined]
**bDocumenttypeRental** | **boolean** | Whether if it\&#39;s an rental | [default to undefined]
**bDocumenttypeReference** | **boolean** | Whether if it\&#39;s an reference | [default to undefined]
**bDocumenttypeMortgagereference** | **boolean** | Whether if it\&#39;s an mortgagereference | [default to undefined]
**bDocumenttypeEvaluation** | **boolean** | Whether if it\&#39;s an evaluation | [default to undefined]
**bDocumenttypeConsultation** | **boolean** | Whether if it\&#39;s an consultation | [default to undefined]
**bDocumenttypeOtherservices** | **boolean** | Whether if it\&#39;s an otherservices | [default to undefined]
**bDocumenttypeForeclosedsale** | **boolean** | Whether if it\&#39;s an foreclosedsale | [default to undefined]
**bDocumenttypeCommercialfunding** | **boolean** | Whether if it\&#39;s an commercialfunding | [default to undefined]
**bDocumenttypeCanafe** | **boolean** | Whether if it\&#39;s an canafe | [default to undefined]
**eDocumenttypeEzcom** | [**FieldEDocumenttypeEzcom**](FieldEDocumenttypeEzcom.md) |  | [optional] [default to undefined]
**eDocumenttypePrivacydefault** | [**FieldEDocumenttypePrivacydefault**](FieldEDocumenttypePrivacydefault.md) |  | [default to undefined]
**eDocumenttypeStatusdefault** | [**FieldEDocumenttypeStatusdefault**](FieldEDocumenttypeStatusdefault.md) |  | [default to undefined]
**eDocumenttypeSalebyowner** | [**FieldEDocumenttypeSalebyowner**](FieldEDocumenttypeSalebyowner.md) |  | [default to undefined]
**eDocumenttypeSaledisplaybyrole** | [**FieldEDocumenttypeSaledisplaybyrole**](FieldEDocumenttypeSaledisplaybyrole.md) |  | [default to undefined]
**eDocumenttypeTransactiontype** | [**FieldEDocumenttypeTransactiontype**](FieldEDocumenttypeTransactiontype.md) |  | [default to undefined]
**eDocumenttypeRepossession** | [**FieldEDocumenttypeRepossession**](FieldEDocumenttypeRepossession.md) |  | [default to undefined]
**a_fkiInscriptiontypeID** | **Array&lt;number&gt;** |  | [default to undefined]

## Example

```typescript
import { DocumenttypeRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DocumenttypeRequest = {
    pkiDocumenttypeID,
    objDocumenttypeName,
    eDocumenttypeStep,
    sDocumenttypeDefaultfilename,
    bDocumenttypeShowagent,
    bDocumenttypeIsactive,
    bDocumenttypeIsrequired,
    bDocumenttypeSale,
    bDocumenttypeRental,
    bDocumenttypeReference,
    bDocumenttypeMortgagereference,
    bDocumenttypeEvaluation,
    bDocumenttypeConsultation,
    bDocumenttypeOtherservices,
    bDocumenttypeForeclosedsale,
    bDocumenttypeCommercialfunding,
    bDocumenttypeCanafe,
    eDocumenttypeEzcom,
    eDocumenttypePrivacydefault,
    eDocumenttypeStatusdefault,
    eDocumenttypeSalebyowner,
    eDocumenttypeSaledisplaybyrole,
    eDocumenttypeTransactiontype,
    eDocumenttypeRepossession,
    a_fkiInscriptiontypeID,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

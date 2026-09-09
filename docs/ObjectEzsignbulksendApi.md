# ObjectEzsignbulksendApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignbulksendCreateEzsignbulksendtransmissionV2**](#ezsignbulksendcreateezsignbulksendtransmissionv2) | **POST** /2/object/ezsignbulksend/{pkiEzsignbulksendID}/createEzsignbulksendtransmission | Create a new Ezsignbulksendtransmission in the Ezsignbulksend|
|[**ezsignbulksendCreateObjectV1**](#ezsignbulksendcreateobjectv1) | **POST** /1/object/ezsignbulksend | Create a new Ezsignbulksend|
|[**ezsignbulksendCreateObjectV2**](#ezsignbulksendcreateobjectv2) | **POST** /2/object/ezsignbulksend | Create a new Ezsignbulksend|
|[**ezsignbulksendDeleteObjectV1**](#ezsignbulksenddeleteobjectv1) | **DELETE** /1/object/ezsignbulksend/{pkiEzsignbulksendID} | Delete an existing Ezsignbulksend|
|[**ezsignbulksendEditObjectV2**](#ezsignbulksendeditobjectv2) | **PUT** /2/object/ezsignbulksend/{pkiEzsignbulksendID} | Edit an existing Ezsignbulksend|
|[**ezsignbulksendGetBatchFileV1**](#ezsignbulksendgetbatchfilev1) | **GET** /1/object/ezsignbulksend/{pkiEzsignbulksendID}/getBatchFile | Retrieve file to download documents in batch|
|[**ezsignbulksendGetCsvTemplateV1**](#ezsignbulksendgetcsvtemplatev1) | **GET** /1/object/ezsignbulksend/{pkiEzsignbulksendID}/getCsvTemplate | Retrieve an existing Ezsignbulksend\&#39;s empty Csv template|
|[**ezsignbulksendGetEzsignbulksendtransmissionsV1**](#ezsignbulksendgetezsignbulksendtransmissionsv1) | **GET** /1/object/ezsignbulksend/{pkiEzsignbulksendID}/getEzsignbulksendtransmissions | Retrieve an existing Ezsignbulksend\&#39;s Ezsignbulksendtransmissions|
|[**ezsignbulksendGetEzsignsignaturesAutomaticV1**](#ezsignbulksendgetezsignsignaturesautomaticv1) | **GET** /1/object/ezsignbulksend/{pkiEzsignbulksendID}/getEzsignsignaturesAutomatic | Retrieve an existing Ezsignbulksend\&#39;s automatic Ezsignsignatures|
|[**ezsignbulksendGetFormsDataV1**](#ezsignbulksendgetformsdatav1) | **GET** /1/object/ezsignbulksend/{pkiEzsignbulksendID}/getFormsData | Retrieve an existing Ezsignbulksend\&#39;s forms data|
|[**ezsignbulksendGetListV1**](#ezsignbulksendgetlistv1) | **GET** /1/object/ezsignbulksend/getList | Retrieve Ezsignbulksend list|
|[**ezsignbulksendGetObjectV2**](#ezsignbulksendgetobjectv2) | **GET** /2/object/ezsignbulksend/{pkiEzsignbulksendID} | Retrieve an existing Ezsignbulksend|
|[**ezsignbulksendGetObjectV3**](#ezsignbulksendgetobjectv3) | **GET** /3/object/ezsignbulksend/{pkiEzsignbulksendID} | Retrieve an existing Ezsignbulksend|
|[**ezsignbulksendGetObjectV4**](#ezsignbulksendgetobjectv4) | **GET** /4/object/ezsignbulksend/{pkiEzsignbulksendID} | Retrieve an existing Ezsignbulksend|
|[**ezsignbulksendReorderV1**](#ezsignbulksendreorderv1) | **POST** /1/object/ezsignbulksend/{pkiEzsignbulksendID}/reorder | Reorder Ezsignbulksenddocumentmappings in the Ezsignbulksend|

# **ezsignbulksendCreateEzsignbulksendtransmissionV2**
> EzsignbulksendCreateEzsignbulksendtransmissionV2Response ezsignbulksendCreateEzsignbulksendtransmissionV2(ezsignbulksendCreateEzsignbulksendtransmissionV2Request)


### Example

```typescript
import {
    ObjectEzsignbulksendApi,
    Configuration,
    EzsignbulksendCreateEzsignbulksendtransmissionV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendApi(configuration);

let pkiEzsignbulksendID: number; // (default to undefined)
let ezsignbulksendCreateEzsignbulksendtransmissionV2Request: EzsignbulksendCreateEzsignbulksendtransmissionV2Request; //

const { status, data } = await apiInstance.ezsignbulksendCreateEzsignbulksendtransmissionV2(
    pkiEzsignbulksendID,
    ezsignbulksendCreateEzsignbulksendtransmissionV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignbulksendCreateEzsignbulksendtransmissionV2Request** | **EzsignbulksendCreateEzsignbulksendtransmissionV2Request**|  | |
| **pkiEzsignbulksendID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksendCreateEzsignbulksendtransmissionV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignbulksendCreateObjectV1**
> EzsignbulksendCreateObjectV1Response ezsignbulksendCreateObjectV1(ezsignbulksendCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsignbulksendApi,
    Configuration,
    EzsignbulksendCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendApi(configuration);

let ezsignbulksendCreateObjectV1Request: EzsignbulksendCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsignbulksendCreateObjectV1(
    ezsignbulksendCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignbulksendCreateObjectV1Request** | **EzsignbulksendCreateObjectV1Request**|  | |


### Return type

**EzsignbulksendCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignbulksendCreateObjectV2**
> EzsignbulksendCreateObjectV2Response ezsignbulksendCreateObjectV2(ezsignbulksendCreateObjectV2Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsignbulksendApi,
    Configuration,
    EzsignbulksendCreateObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendApi(configuration);

let ezsignbulksendCreateObjectV2Request: EzsignbulksendCreateObjectV2Request; //

const { status, data } = await apiInstance.ezsignbulksendCreateObjectV2(
    ezsignbulksendCreateObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignbulksendCreateObjectV2Request** | **EzsignbulksendCreateObjectV2Request**|  | |


### Return type

**EzsignbulksendCreateObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignbulksendDeleteObjectV1**
> EzsignbulksendDeleteObjectV1Response ezsignbulksendDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsignbulksendApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendApi(configuration);

let pkiEzsignbulksendID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendDeleteObjectV1(
    pkiEzsignbulksendID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksendDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignbulksendEditObjectV2**
> EzsignbulksendEditObjectV2Response ezsignbulksendEditObjectV2(ezsignbulksendEditObjectV2Request)



### Example

```typescript
import {
    ObjectEzsignbulksendApi,
    Configuration,
    EzsignbulksendEditObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendApi(configuration);

let pkiEzsignbulksendID: number; // (default to undefined)
let ezsignbulksendEditObjectV2Request: EzsignbulksendEditObjectV2Request; //

const { status, data } = await apiInstance.ezsignbulksendEditObjectV2(
    pkiEzsignbulksendID,
    ezsignbulksendEditObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignbulksendEditObjectV2Request** | **EzsignbulksendEditObjectV2Request**|  | |
| **pkiEzsignbulksendID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksendEditObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignbulksendGetBatchFileV1**
> File ezsignbulksendGetBatchFileV1()


### Example

```typescript
import {
    ObjectEzsignbulksendApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendApi(configuration);

let pkiEzsignbulksendID: number; // (default to undefined)
let bIncludeSigned: boolean; //Include final document once all signatures were applied (optional) (default to undefined)
let bIncludeAttachment: boolean; //Include attached files in signatures (optional) (default to undefined)
let bIncludeProofdocument: boolean; //Include the evidence report (optional) (default to undefined)
let bIncludeProof: boolean; //include the complete evidence archive including all of the above and more (optional) (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendGetBatchFileV1(
    pkiEzsignbulksendID,
    bIncludeSigned,
    bIncludeAttachment,
    bIncludeProofdocument,
    bIncludeProof
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendID** | [**number**] |  | defaults to undefined|
| **bIncludeSigned** | [**boolean**] | Include final document once all signatures were applied | (optional) defaults to undefined|
| **bIncludeAttachment** | [**boolean**] | Include attached files in signatures | (optional) defaults to undefined|
| **bIncludeProofdocument** | [**boolean**] | Include the evidence report | (optional) defaults to undefined|
| **bIncludeProof** | [**boolean**] | include the complete evidence archive including all of the above and more | (optional) defaults to undefined|


### Return type

**File**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: text/xml, application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignbulksendGetCsvTemplateV1**
> string ezsignbulksendGetCsvTemplateV1()



### Example

```typescript
import {
    ObjectEzsignbulksendApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendApi(configuration);

let pkiEzsignbulksendID: number; // (default to undefined)
let eCsvSeparator: 'Comma' | 'Semicolon'; //Separator that will be used to separate fields (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendGetCsvTemplateV1(
    pkiEzsignbulksendID,
    eCsvSeparator
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendID** | [**number**] |  | defaults to undefined|
| **eCsvSeparator** | [**&#39;Comma&#39; | &#39;Semicolon&#39;**]**Array<&#39;Comma&#39; &#124; &#39;Semicolon&#39;>** | Separator that will be used to separate fields | defaults to undefined|


### Return type

**string**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: text/csv, application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignbulksendGetEzsignbulksendtransmissionsV1**
> EzsignbulksendGetEzsignbulksendtransmissionsV1Response ezsignbulksendGetEzsignbulksendtransmissionsV1()



### Example

```typescript
import {
    ObjectEzsignbulksendApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendApi(configuration);

let pkiEzsignbulksendID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendGetEzsignbulksendtransmissionsV1(
    pkiEzsignbulksendID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksendGetEzsignbulksendtransmissionsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignbulksendGetEzsignsignaturesAutomaticV1**
> EzsignbulksendGetEzsignsignaturesAutomaticV1Response ezsignbulksendGetEzsignsignaturesAutomaticV1()

Return the Ezsignsignatures that can be signed by the current user at the current step in the process

### Example

```typescript
import {
    ObjectEzsignbulksendApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendApi(configuration);

let pkiEzsignbulksendID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendGetEzsignsignaturesAutomaticV1(
    pkiEzsignbulksendID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksendGetEzsignsignaturesAutomaticV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignbulksendGetFormsDataV1**
> EzsignbulksendGetFormsDataV1Response ezsignbulksendGetFormsDataV1()



### Example

```typescript
import {
    ObjectEzsignbulksendApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendApi(configuration);

let pkiEzsignbulksendID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendGetFormsDataV1(
    pkiEzsignbulksendID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksendGetFormsDataV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/zip


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignbulksendGetListV1**
> EzsignbulksendGetListV1Response ezsignbulksendGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eEzsignfoldertypePrivacylevel | User<br>Usergroup |

### Example

```typescript
import {
    ObjectEzsignbulksendApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendApi(configuration);

let eOrderBy: 'pkiEzsignbulksendID_ASC' | 'pkiEzsignbulksendID_DESC' | 'fkiEzsignfoldertypeID_ASC' | 'fkiEzsignfoldertypeID_DESC' | 'sEzsignbulksendDescription_ASC' | 'sEzsignbulksendDescription_DESC' | 'sEzsignfoldertypeNameX_ASC' | 'sEzsignfoldertypeNameX_DESC' | 'eEzsignfoldertypePrivacylevel_ASC' | 'eEzsignfoldertypePrivacylevel_DESC' | 'bEzsignbulksendNeedvalidation_ASC' | 'bEzsignbulksendNeedvalidation_DESC' | 'iEzsignbulksendtransmission_ASC' | 'iEzsignbulksendtransmission_DESC' | 'iEzsignfolder_ASC' | 'iEzsignfolder_DESC' | 'iEzsigndocument_ASC' | 'iEzsigndocument_DESC' | 'iEzsignsignature_ASC' | 'iEzsignsignature_DESC' | 'iEzsignsignatureSigned_ASC' | 'iEzsignsignatureSigned_DESC' | 'bEzsignbulksendIsactive_ASC' | 'bEzsignbulksendIsactive_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendGetListV1(
    eOrderBy,
    iRowMax,
    iRowOffset,
    acceptLanguage,
    sFilter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eOrderBy** | [**&#39;pkiEzsignbulksendID_ASC&#39; | &#39;pkiEzsignbulksendID_DESC&#39; | &#39;fkiEzsignfoldertypeID_ASC&#39; | &#39;fkiEzsignfoldertypeID_DESC&#39; | &#39;sEzsignbulksendDescription_ASC&#39; | &#39;sEzsignbulksendDescription_DESC&#39; | &#39;sEzsignfoldertypeNameX_ASC&#39; | &#39;sEzsignfoldertypeNameX_DESC&#39; | &#39;eEzsignfoldertypePrivacylevel_ASC&#39; | &#39;eEzsignfoldertypePrivacylevel_DESC&#39; | &#39;bEzsignbulksendNeedvalidation_ASC&#39; | &#39;bEzsignbulksendNeedvalidation_DESC&#39; | &#39;iEzsignbulksendtransmission_ASC&#39; | &#39;iEzsignbulksendtransmission_DESC&#39; | &#39;iEzsignfolder_ASC&#39; | &#39;iEzsignfolder_DESC&#39; | &#39;iEzsigndocument_ASC&#39; | &#39;iEzsigndocument_DESC&#39; | &#39;iEzsignsignature_ASC&#39; | &#39;iEzsignsignature_DESC&#39; | &#39;iEzsignsignatureSigned_ASC&#39; | &#39;iEzsignsignatureSigned_DESC&#39; | &#39;bEzsignbulksendIsactive_ASC&#39; | &#39;bEzsignbulksendIsactive_DESC&#39;**]**Array<&#39;pkiEzsignbulksendID_ASC&#39; &#124; &#39;pkiEzsignbulksendID_DESC&#39; &#124; &#39;fkiEzsignfoldertypeID_ASC&#39; &#124; &#39;fkiEzsignfoldertypeID_DESC&#39; &#124; &#39;sEzsignbulksendDescription_ASC&#39; &#124; &#39;sEzsignbulksendDescription_DESC&#39; &#124; &#39;sEzsignfoldertypeNameX_ASC&#39; &#124; &#39;sEzsignfoldertypeNameX_DESC&#39; &#124; &#39;eEzsignfoldertypePrivacylevel_ASC&#39; &#124; &#39;eEzsignfoldertypePrivacylevel_DESC&#39; &#124; &#39;bEzsignbulksendNeedvalidation_ASC&#39; &#124; &#39;bEzsignbulksendNeedvalidation_DESC&#39; &#124; &#39;iEzsignbulksendtransmission_ASC&#39; &#124; &#39;iEzsignbulksendtransmission_DESC&#39; &#124; &#39;iEzsignfolder_ASC&#39; &#124; &#39;iEzsignfolder_DESC&#39; &#124; &#39;iEzsigndocument_ASC&#39; &#124; &#39;iEzsigndocument_DESC&#39; &#124; &#39;iEzsignsignature_ASC&#39; &#124; &#39;iEzsignsignature_DESC&#39; &#124; &#39;iEzsignsignatureSigned_ASC&#39; &#124; &#39;iEzsignsignatureSigned_DESC&#39; &#124; &#39;bEzsignbulksendIsactive_ASC&#39; &#124; &#39;bEzsignbulksendIsactive_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**EzsignbulksendGetListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignbulksendGetObjectV2**
> EzsignbulksendGetObjectV2Response ezsignbulksendGetObjectV2()



### Example

```typescript
import {
    ObjectEzsignbulksendApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendApi(configuration);

let pkiEzsignbulksendID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendGetObjectV2(
    pkiEzsignbulksendID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksendGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignbulksendGetObjectV3**
> EzsignbulksendGetObjectV3Response ezsignbulksendGetObjectV3()



### Example

```typescript
import {
    ObjectEzsignbulksendApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendApi(configuration);

let pkiEzsignbulksendID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendGetObjectV3(
    pkiEzsignbulksendID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksendGetObjectV3Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignbulksendGetObjectV4**
> EzsignbulksendGetObjectV4Response ezsignbulksendGetObjectV4()



### Example

```typescript
import {
    ObjectEzsignbulksendApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendApi(configuration);

let pkiEzsignbulksendID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendGetObjectV4(
    pkiEzsignbulksendID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksendGetObjectV4Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignbulksendReorderV1**
> EzsignbulksendReorderV1Response ezsignbulksendReorderV1(ezsignbulksendReorderV1Request)


### Example

```typescript
import {
    ObjectEzsignbulksendApi,
    Configuration,
    EzsignbulksendReorderV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendApi(configuration);

let pkiEzsignbulksendID: number; // (default to undefined)
let ezsignbulksendReorderV1Request: EzsignbulksendReorderV1Request; //

const { status, data } = await apiInstance.ezsignbulksendReorderV1(
    pkiEzsignbulksendID,
    ezsignbulksendReorderV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignbulksendReorderV1Request** | **EzsignbulksendReorderV1Request**|  | |
| **pkiEzsignbulksendID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksendReorderV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


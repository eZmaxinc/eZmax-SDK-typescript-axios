# ObjectEzsignbulksendtransmissionApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignbulksendtransmissionGetBatchFileV1**](#ezsignbulksendtransmissiongetbatchfilev1) | **GET** /1/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}/getBatchFile | Retrieve file to download documents in batch|
|[**ezsignbulksendtransmissionGetCsvErrorsV1**](#ezsignbulksendtransmissiongetcsverrorsv1) | **GET** /1/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}/getCsvErrors | Retrieve an existing Ezsignbulksendtransmission\&#39;s Csv containing errors|
|[**ezsignbulksendtransmissionGetEzsignsignaturesAutomaticV1**](#ezsignbulksendtransmissiongetezsignsignaturesautomaticv1) | **GET** /1/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}/getEzsignsignaturesAutomatic | Retrieve an existing Ezsignbulksendtransmission\&#39;s automatic Ezsignsignatures|
|[**ezsignbulksendtransmissionGetFormsDataV1**](#ezsignbulksendtransmissiongetformsdatav1) | **GET** /1/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}/getFormsData | Retrieve an existing Ezsignbulksendtransmission\&#39;s forms data|
|[**ezsignbulksendtransmissionGetObjectV2**](#ezsignbulksendtransmissiongetobjectv2) | **GET** /2/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID} | Retrieve an existing Ezsignbulksendtransmission|

# **ezsignbulksendtransmissionGetBatchFileV1**
> File ezsignbulksendtransmissionGetBatchFileV1()


### Example

```typescript
import {
    ObjectEzsignbulksendtransmissionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendtransmissionApi(configuration);

let pkiEzsignbulksendtransmissionID: number; // (default to undefined)
let bIncludeSigned: boolean; //Include final document once all signatures were applied (optional) (default to undefined)
let bIncludeAttachment: boolean; //Include attached files in signatures (optional) (default to undefined)
let bIncludeProofdocument: boolean; //Include the evidence report (optional) (default to undefined)
let bIncludeProof: boolean; //include the complete evidence archive including all of the above and more (optional) (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendtransmissionGetBatchFileV1(
    pkiEzsignbulksendtransmissionID,
    bIncludeSigned,
    bIncludeAttachment,
    bIncludeProofdocument,
    bIncludeProof
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendtransmissionID** | [**number**] |  | defaults to undefined|
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

# **ezsignbulksendtransmissionGetCsvErrorsV1**
> string ezsignbulksendtransmissionGetCsvErrorsV1()



### Example

```typescript
import {
    ObjectEzsignbulksendtransmissionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendtransmissionApi(configuration);

let pkiEzsignbulksendtransmissionID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendtransmissionGetCsvErrorsV1(
    pkiEzsignbulksendtransmissionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendtransmissionID** | [**number**] |  | defaults to undefined|


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

# **ezsignbulksendtransmissionGetEzsignsignaturesAutomaticV1**
> EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response ezsignbulksendtransmissionGetEzsignsignaturesAutomaticV1()

Return the Ezsignsignatures that can be signed by the current user at the current step in the process

### Example

```typescript
import {
    ObjectEzsignbulksendtransmissionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendtransmissionApi(configuration);

let pkiEzsignbulksendtransmissionID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendtransmissionGetEzsignsignaturesAutomaticV1(
    pkiEzsignbulksendtransmissionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendtransmissionID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response**

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

# **ezsignbulksendtransmissionGetFormsDataV1**
> EzsignbulksendtransmissionGetFormsDataV1Response ezsignbulksendtransmissionGetFormsDataV1()



### Example

```typescript
import {
    ObjectEzsignbulksendtransmissionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendtransmissionApi(configuration);

let pkiEzsignbulksendtransmissionID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendtransmissionGetFormsDataV1(
    pkiEzsignbulksendtransmissionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendtransmissionID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksendtransmissionGetFormsDataV1Response**

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

# **ezsignbulksendtransmissionGetObjectV2**
> EzsignbulksendtransmissionGetObjectV2Response ezsignbulksendtransmissionGetObjectV2()



### Example

```typescript
import {
    ObjectEzsignbulksendtransmissionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignbulksendtransmissionApi(configuration);

let pkiEzsignbulksendtransmissionID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignbulksendtransmissionGetObjectV2(
    pkiEzsignbulksendtransmissionID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignbulksendtransmissionID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignbulksendtransmissionGetObjectV2Response**

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


# ObjectDocumenttypechecklistApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**documenttypechecklistCreateObjectV1**](#documenttypechecklistcreateobjectv1) | **POST** /1/object/documenttypechecklist | Create a new Documenttypechecklist|
|[**documenttypechecklistDeleteObjectV1**](#documenttypechecklistdeleteobjectv1) | **DELETE** /1/object/documenttypechecklist/{pkiDocumenttypechecklistID} | Delete an existing Documenttypechecklist|
|[**documenttypechecklistEditObjectV1**](#documenttypechecklisteditobjectv1) | **PUT** /1/object/documenttypechecklist/{pkiDocumenttypechecklistID} | Edit an existing Documenttypechecklist|
|[**documenttypechecklistGetListV1**](#documenttypechecklistgetlistv1) | **GET** /1/object/documenttypechecklist/getList | Retrieve Documenttypechecklist list|
|[**documenttypechecklistGetObjectV2**](#documenttypechecklistgetobjectv2) | **GET** /2/object/documenttypechecklist/{pkiDocumenttypechecklistID} | Retrieve an existing Documenttypechecklist|

# **documenttypechecklistCreateObjectV1**
> DocumenttypechecklistCreateObjectV1Response documenttypechecklistCreateObjectV1(documenttypechecklistCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectDocumenttypechecklistApi,
    Configuration,
    DocumenttypechecklistCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDocumenttypechecklistApi(configuration);

let documenttypechecklistCreateObjectV1Request: DocumenttypechecklistCreateObjectV1Request; //

const { status, data } = await apiInstance.documenttypechecklistCreateObjectV1(
    documenttypechecklistCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **documenttypechecklistCreateObjectV1Request** | **DocumenttypechecklistCreateObjectV1Request**|  | |


### Return type

**DocumenttypechecklistCreateObjectV1Response**

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

# **documenttypechecklistDeleteObjectV1**
> DocumenttypechecklistDeleteObjectV1Response documenttypechecklistDeleteObjectV1()



### Example

```typescript
import {
    ObjectDocumenttypechecklistApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDocumenttypechecklistApi(configuration);

let pkiDocumenttypechecklistID: number; //The unique ID of the Documenttypechecklist (default to undefined)

const { status, data } = await apiInstance.documenttypechecklistDeleteObjectV1(
    pkiDocumenttypechecklistID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDocumenttypechecklistID** | [**number**] | The unique ID of the Documenttypechecklist | defaults to undefined|


### Return type

**DocumenttypechecklistDeleteObjectV1Response**

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

# **documenttypechecklistEditObjectV1**
> DocumenttypechecklistEditObjectV1Response documenttypechecklistEditObjectV1(documenttypechecklistEditObjectV1Request)



### Example

```typescript
import {
    ObjectDocumenttypechecklistApi,
    Configuration,
    DocumenttypechecklistEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDocumenttypechecklistApi(configuration);

let pkiDocumenttypechecklistID: number; //The unique ID of the Documenttypechecklist (default to undefined)
let documenttypechecklistEditObjectV1Request: DocumenttypechecklistEditObjectV1Request; //

const { status, data } = await apiInstance.documenttypechecklistEditObjectV1(
    pkiDocumenttypechecklistID,
    documenttypechecklistEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **documenttypechecklistEditObjectV1Request** | **DocumenttypechecklistEditObjectV1Request**|  | |
| **pkiDocumenttypechecklistID** | [**number**] | The unique ID of the Documenttypechecklist | defaults to undefined|


### Return type

**DocumenttypechecklistEditObjectV1Response**

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

# **documenttypechecklistGetListV1**
> DocumenttypechecklistGetListV1Response documenttypechecklistGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eDocumenttypechecklistStatus | Not required<br>Required<br>Filed<br>Justified |

### Example

```typescript
import {
    ObjectDocumenttypechecklistApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDocumenttypechecklistApi(configuration);

let eOrderBy: 'pkiDocumenttypechecklistID_ASC' | 'pkiDocumenttypechecklistID_DESC' | 'fkiDocumenttypeID_ASC' | 'fkiDocumenttypeID_DESC' | 'eDocumenttypechecklistStatus_ASC' | 'eDocumenttypechecklistStatus_DESC' | 'tDocumenttypechecklistComment_ASC' | 'tDocumenttypechecklistComment_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.documenttypechecklistGetListV1(
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
| **eOrderBy** | [**&#39;pkiDocumenttypechecklistID_ASC&#39; | &#39;pkiDocumenttypechecklistID_DESC&#39; | &#39;fkiDocumenttypeID_ASC&#39; | &#39;fkiDocumenttypeID_DESC&#39; | &#39;eDocumenttypechecklistStatus_ASC&#39; | &#39;eDocumenttypechecklistStatus_DESC&#39; | &#39;tDocumenttypechecklistComment_ASC&#39; | &#39;tDocumenttypechecklistComment_DESC&#39;**]**Array<&#39;pkiDocumenttypechecklistID_ASC&#39; &#124; &#39;pkiDocumenttypechecklistID_DESC&#39; &#124; &#39;fkiDocumenttypeID_ASC&#39; &#124; &#39;fkiDocumenttypeID_DESC&#39; &#124; &#39;eDocumenttypechecklistStatus_ASC&#39; &#124; &#39;eDocumenttypechecklistStatus_DESC&#39; &#124; &#39;tDocumenttypechecklistComment_ASC&#39; &#124; &#39;tDocumenttypechecklistComment_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**DocumenttypechecklistGetListV1Response**

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

# **documenttypechecklistGetObjectV2**
> DocumenttypechecklistGetObjectV2Response documenttypechecklistGetObjectV2()



### Example

```typescript
import {
    ObjectDocumenttypechecklistApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDocumenttypechecklistApi(configuration);

let pkiDocumenttypechecklistID: number; //The unique ID of the Documenttypechecklist (default to undefined)

const { status, data } = await apiInstance.documenttypechecklistGetObjectV2(
    pkiDocumenttypechecklistID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDocumenttypechecklistID** | [**number**] | The unique ID of the Documenttypechecklist | defaults to undefined|


### Return type

**DocumenttypechecklistGetObjectV2Response**

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


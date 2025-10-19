# ObjectEzsignfoldersignerassociationApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignfoldersignerassociationCreateEmbeddedUrlV1**](#ezsignfoldersignerassociationcreateembeddedurlv1) | **POST** /1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}/createEmbeddedUrl | Creates an Url to allow embedded signing|
|[**ezsignfoldersignerassociationCreateEmbeddedUrlV2**](#ezsignfoldersignerassociationcreateembeddedurlv2) | **POST** /2/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}/createEmbeddedUrl | Creates an Url to allow embedded signing|
|[**ezsignfoldersignerassociationCreateObjectV1**](#ezsignfoldersignerassociationcreateobjectv1) | **POST** /1/object/ezsignfoldersignerassociation | Create a new Ezsignfoldersignerassociation|
|[**ezsignfoldersignerassociationCreateObjectV2**](#ezsignfoldersignerassociationcreateobjectv2) | **POST** /2/object/ezsignfoldersignerassociation | Create a new Ezsignfoldersignerassociation|
|[**ezsignfoldersignerassociationDeleteObjectV1**](#ezsignfoldersignerassociationdeleteobjectv1) | **DELETE** /1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID} | Delete an existing Ezsignfoldersignerassociation|
|[**ezsignfoldersignerassociationEditObjectV1**](#ezsignfoldersignerassociationeditobjectv1) | **PUT** /1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID} | Edit an existing Ezsignfoldersignerassociation|
|[**ezsignfoldersignerassociationForceDisconnectV1**](#ezsignfoldersignerassociationforcedisconnectv1) | **POST** /1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}/forceDisconnect | Disconnects the Ezsignfoldersignerassociation|
|[**ezsignfoldersignerassociationGetInPersonLoginUrlV1**](#ezsignfoldersignerassociationgetinpersonloginurlv1) | **GET** /1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}/getInPersonLoginUrl | Retrieve a Login Url to allow In-Person signing|
|[**ezsignfoldersignerassociationGetObjectV1**](#ezsignfoldersignerassociationgetobjectv1) | **GET** /1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID} | Retrieve an existing Ezsignfoldersignerassociation|
|[**ezsignfoldersignerassociationGetObjectV2**](#ezsignfoldersignerassociationgetobjectv2) | **GET** /2/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID} | Retrieve an existing Ezsignfoldersignerassociation|
|[**ezsignfoldersignerassociationPatchObjectV1**](#ezsignfoldersignerassociationpatchobjectv1) | **PATCH** /1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID} | Patch an existing Ezsignfoldersignerassociation|
|[**ezsignfoldersignerassociationReassignV1**](#ezsignfoldersignerassociationreassignv1) | **POST** /1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}/reassign | Reassign remaining unsigned signatures and forms|

# **ezsignfoldersignerassociationCreateEmbeddedUrlV1**
> EzsignfoldersignerassociationCreateEmbeddedUrlV1Response ezsignfoldersignerassociationCreateEmbeddedUrlV1(ezsignfoldersignerassociationCreateEmbeddedUrlV1Request)

This endpoint creates an Url that can be used in a browser or embedded in an I-Frame to allow signing.  The signer Login type must be configured as Embedded.

### Example

```typescript
import {
    ObjectEzsignfoldersignerassociationApi,
    Configuration,
    EzsignfoldersignerassociationCreateEmbeddedUrlV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldersignerassociationApi(configuration);

let pkiEzsignfoldersignerassociationID: number; // (default to undefined)
let ezsignfoldersignerassociationCreateEmbeddedUrlV1Request: EzsignfoldersignerassociationCreateEmbeddedUrlV1Request; //

const { status, data } = await apiInstance.ezsignfoldersignerassociationCreateEmbeddedUrlV1(
    pkiEzsignfoldersignerassociationID,
    ezsignfoldersignerassociationCreateEmbeddedUrlV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfoldersignerassociationCreateEmbeddedUrlV1Request** | **EzsignfoldersignerassociationCreateEmbeddedUrlV1Request**|  | |
| **pkiEzsignfoldersignerassociationID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfoldersignerassociationCreateEmbeddedUrlV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfoldersignerassociationCreateEmbeddedUrlV2**
> EzsignfoldersignerassociationCreateEmbeddedUrlV2Response ezsignfoldersignerassociationCreateEmbeddedUrlV2(ezsignfoldersignerassociationCreateEmbeddedUrlV2Request)

This endpoint creates an Url that can be used in a browser or embedded in an I-Frame to allow signing.  The signer Login type must be configured as Embedded.

### Example

```typescript
import {
    ObjectEzsignfoldersignerassociationApi,
    Configuration,
    EzsignfoldersignerassociationCreateEmbeddedUrlV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldersignerassociationApi(configuration);

let pkiEzsignfoldersignerassociationID: number; // (default to undefined)
let ezsignfoldersignerassociationCreateEmbeddedUrlV2Request: EzsignfoldersignerassociationCreateEmbeddedUrlV2Request; //

const { status, data } = await apiInstance.ezsignfoldersignerassociationCreateEmbeddedUrlV2(
    pkiEzsignfoldersignerassociationID,
    ezsignfoldersignerassociationCreateEmbeddedUrlV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfoldersignerassociationCreateEmbeddedUrlV2Request** | **EzsignfoldersignerassociationCreateEmbeddedUrlV2Request**|  | |
| **pkiEzsignfoldersignerassociationID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfoldersignerassociationCreateEmbeddedUrlV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfoldersignerassociationCreateObjectV1**
> EzsignfoldersignerassociationCreateObjectV1Response ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request)

The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.

### Example

```typescript
import {
    ObjectEzsignfoldersignerassociationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldersignerassociationApi(configuration);

let ezsignfoldersignerassociationCreateObjectV1Request: Array<EzsignfoldersignerassociationCreateObjectV1Request>; //

const { status, data } = await apiInstance.ezsignfoldersignerassociationCreateObjectV1(
    ezsignfoldersignerassociationCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfoldersignerassociationCreateObjectV1Request** | **Array<EzsignfoldersignerassociationCreateObjectV1Request>**|  | |


### Return type

**EzsignfoldersignerassociationCreateObjectV1Response**

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

# **ezsignfoldersignerassociationCreateObjectV2**
> EzsignfoldersignerassociationCreateObjectV2Response ezsignfoldersignerassociationCreateObjectV2(ezsignfoldersignerassociationCreateObjectV2Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsignfoldersignerassociationApi,
    Configuration,
    EzsignfoldersignerassociationCreateObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldersignerassociationApi(configuration);

let ezsignfoldersignerassociationCreateObjectV2Request: EzsignfoldersignerassociationCreateObjectV2Request; //

const { status, data } = await apiInstance.ezsignfoldersignerassociationCreateObjectV2(
    ezsignfoldersignerassociationCreateObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfoldersignerassociationCreateObjectV2Request** | **EzsignfoldersignerassociationCreateObjectV2Request**|  | |


### Return type

**EzsignfoldersignerassociationCreateObjectV2Response**

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

# **ezsignfoldersignerassociationDeleteObjectV1**
> EzsignfoldersignerassociationDeleteObjectV1Response ezsignfoldersignerassociationDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsignfoldersignerassociationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldersignerassociationApi(configuration);

let pkiEzsignfoldersignerassociationID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfoldersignerassociationDeleteObjectV1(
    pkiEzsignfoldersignerassociationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfoldersignerassociationID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfoldersignerassociationDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfoldersignerassociationEditObjectV1**
> EzsignfoldersignerassociationEditObjectV1Response ezsignfoldersignerassociationEditObjectV1(ezsignfoldersignerassociationEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzsignfoldersignerassociationApi,
    Configuration,
    EzsignfoldersignerassociationEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldersignerassociationApi(configuration);

let pkiEzsignfoldersignerassociationID: number; // (default to undefined)
let ezsignfoldersignerassociationEditObjectV1Request: EzsignfoldersignerassociationEditObjectV1Request; //

const { status, data } = await apiInstance.ezsignfoldersignerassociationEditObjectV1(
    pkiEzsignfoldersignerassociationID,
    ezsignfoldersignerassociationEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfoldersignerassociationEditObjectV1Request** | **EzsignfoldersignerassociationEditObjectV1Request**|  | |
| **pkiEzsignfoldersignerassociationID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfoldersignerassociationEditObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfoldersignerassociationForceDisconnectV1**
> EzsignfoldersignerassociationForceDisconnectV1Response ezsignfoldersignerassociationForceDisconnectV1(body)



### Example

```typescript
import {
    ObjectEzsignfoldersignerassociationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldersignerassociationApi(configuration);

let pkiEzsignfoldersignerassociationID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.ezsignfoldersignerassociationForceDisconnectV1(
    pkiEzsignfoldersignerassociationID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiEzsignfoldersignerassociationID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfoldersignerassociationForceDisconnectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfoldersignerassociationGetInPersonLoginUrlV1**
> EzsignfoldersignerassociationGetInPersonLoginUrlV1Response ezsignfoldersignerassociationGetInPersonLoginUrlV1()

This endpoint returns a Login Url that can be used in a browser or embedded in an I-Frame to allow in person signing.  The signer Login type must be configured as In-Person.

### Example

```typescript
import {
    ObjectEzsignfoldersignerassociationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldersignerassociationApi(configuration);

let pkiEzsignfoldersignerassociationID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfoldersignerassociationGetInPersonLoginUrlV1(
    pkiEzsignfoldersignerassociationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfoldersignerassociationID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfoldersignerassociationGetInPersonLoginUrlV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfoldersignerassociationGetObjectV1**
> EzsignfoldersignerassociationGetObjectV1Response ezsignfoldersignerassociationGetObjectV1()



### Example

```typescript
import {
    ObjectEzsignfoldersignerassociationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldersignerassociationApi(configuration);

let pkiEzsignfoldersignerassociationID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfoldersignerassociationGetObjectV1(
    pkiEzsignfoldersignerassociationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfoldersignerassociationID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfoldersignerassociationGetObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfoldersignerassociationGetObjectV2**
> EzsignfoldersignerassociationGetObjectV2Response ezsignfoldersignerassociationGetObjectV2()



### Example

```typescript
import {
    ObjectEzsignfoldersignerassociationApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldersignerassociationApi(configuration);

let pkiEzsignfoldersignerassociationID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignfoldersignerassociationGetObjectV2(
    pkiEzsignfoldersignerassociationID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignfoldersignerassociationID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfoldersignerassociationGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfoldersignerassociationPatchObjectV1**
> EzsignfoldersignerassociationPatchObjectV1Response ezsignfoldersignerassociationPatchObjectV1(ezsignfoldersignerassociationPatchObjectV1Request)


### Example

```typescript
import {
    ObjectEzsignfoldersignerassociationApi,
    Configuration,
    EzsignfoldersignerassociationPatchObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldersignerassociationApi(configuration);

let pkiEzsignfoldersignerassociationID: number; // (default to undefined)
let ezsignfoldersignerassociationPatchObjectV1Request: EzsignfoldersignerassociationPatchObjectV1Request; //

const { status, data } = await apiInstance.ezsignfoldersignerassociationPatchObjectV1(
    pkiEzsignfoldersignerassociationID,
    ezsignfoldersignerassociationPatchObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfoldersignerassociationPatchObjectV1Request** | **EzsignfoldersignerassociationPatchObjectV1Request**|  | |
| **pkiEzsignfoldersignerassociationID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfoldersignerassociationPatchObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignfoldersignerassociationReassignV1**
> EzsignfoldersignerassociationReassignV1Response ezsignfoldersignerassociationReassignV1(ezsignfoldersignerassociationReassignV1Request)

Reassign remaining unsigned signatures and forms

### Example

```typescript
import {
    ObjectEzsignfoldersignerassociationApi,
    Configuration,
    EzsignfoldersignerassociationReassignV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignfoldersignerassociationApi(configuration);

let pkiEzsignfoldersignerassociationID: number; // (default to undefined)
let ezsignfoldersignerassociationReassignV1Request: EzsignfoldersignerassociationReassignV1Request; //

const { status, data } = await apiInstance.ezsignfoldersignerassociationReassignV1(
    pkiEzsignfoldersignerassociationID,
    ezsignfoldersignerassociationReassignV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignfoldersignerassociationReassignV1Request** | **EzsignfoldersignerassociationReassignV1Request**|  | |
| **pkiEzsignfoldersignerassociationID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignfoldersignerassociationReassignV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationCreateEmbeddedUrlV1ResponseMPayload } from './ezsignfoldersignerassociation-create-embedded-url-v1-response-mpayload';

/**
 * @type EzsignfoldersignerassociationCreateEmbeddedUrlV1Response
 * Response for POST /1/object/ezsignfoldersignerassociation/createEmbeddedUrl
 * @export
 */
/*export type EzsignfoldersignerassociationCreateEmbeddedUrlV1Response = CommonResponse;*/
export interface EzsignfoldersignerassociationCreateEmbeddedUrlV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignfoldersignerassociationCreateEmbeddedUrlV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfoldersignerassociationCreateEmbeddedUrlV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignfoldersignerassociationCreateEmbeddedUrlV1ResponseMPayload}
     * @memberof EzsignfoldersignerassociationCreateEmbeddedUrlV1Response
     */
    mPayload:EzsignfoldersignerassociationCreateEmbeddedUrlV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectEzsignfoldersignerassociationCreateEmbeddedUrlV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignfoldersignerassociationCreateEmbeddedUrlV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfoldersignerassociationCreateEmbeddedUrlV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationCreateEmbeddedUrlV1Response
 */
export class DataObjectEzsignfoldersignerassociationCreateEmbeddedUrlV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignfoldersignerassociationCreateEmbeddedUrlV1ResponseMPayload = new DataObjectEzsignfoldersignerassociationCreateEmbeddedUrlV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfoldersignerassociationCreateEmbeddedUrlV1Response Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationCreateEmbeddedUrlV1Response
 */
export class ValidationObjectEzsignfoldersignerassociationCreateEmbeddedUrlV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignfoldersignerassociationCreateEmbeddedUrlV1ResponseMPayload()
} 


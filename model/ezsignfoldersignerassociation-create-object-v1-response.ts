/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignfoldersignerassociationCreateObjectV1ResponseMPayload } from './ezsignfoldersignerassociation-create-object-v1-response-mpayload';

/**
 * @type EzsignfoldersignerassociationCreateObjectV1Response
 * Response for POST /1/object/ezsignfoldersignerassociation
 * @export
 */
/*export type EzsignfoldersignerassociationCreateObjectV1Response = CommonResponse;*/
export interface EzsignfoldersignerassociationCreateObjectV1Response {
    /**
     * 
     * @type {EzsignfoldersignerassociationCreateObjectV1ResponseMPayload}
     * @memberof EzsignfoldersignerassociationCreateObjectV1Response
     */
    mPayload:EzsignfoldersignerassociationCreateObjectV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfoldersignerassociationCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignfoldersignerassociationCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfoldersignerassociationCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationCreateObjectV1Response
 */
export class DataObjectEzsignfoldersignerassociationCreateObjectV1Response {
    mPayload:EzsignfoldersignerassociationCreateObjectV1ResponseMPayload = new DataObjectEzsignfoldersignerassociationCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfoldersignerassociationCreateObjectV1Response Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationCreateObjectV1Response
 */
export class ValidationObjectEzsignfoldersignerassociationCreateObjectV1Response {
   mPayload = new ValidationObjectEzsignfoldersignerassociationCreateObjectV1ResponseMPayload()
} 



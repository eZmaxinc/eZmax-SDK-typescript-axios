/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
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
import { EzsignfoldersignerassociationGetObjectV1ResponseAllOf } from './ezsignfoldersignerassociation-get-object-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationGetObjectV1ResponseMPayload } from './ezsignfoldersignerassociation-get-object-v1-response-mpayload';

/**
 * @type EzsignfoldersignerassociationGetObjectV1Response
 * Response for GET /1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}
 * @export
 */
export type EzsignfoldersignerassociationGetObjectV1Response = CommonResponse & EzsignfoldersignerassociationGetObjectV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfoldersignerassociationGetObjectV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignfoldersignerassociationGetObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsignfoldersignerassociationGetObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationGetObjectV1Response
 */
export class DataObjectEzsignfoldersignerassociationGetObjectV1Response {
    mPayload:EzsignfoldersignerassociationGetObjectV1ResponseMPayload = new DataObjectEzsignfoldersignerassociationGetObjectV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsignfoldersignerassociationGetObjectV1Response Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationGetObjectV1Response
 */
export class ValidationObjectEzsignfoldersignerassociationGetObjectV1Response {
   mPayload = new ValidationObjectEzsignfoldersignerassociationGetObjectV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 



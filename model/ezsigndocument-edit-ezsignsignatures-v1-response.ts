/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
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
import { EzsigndocumentEditEzsignsignaturesV1ResponseAllOf } from './ezsigndocument-edit-ezsignsignatures-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentEditEzsignsignaturesV1ResponseMPayload } from './ezsigndocument-edit-ezsignsignatures-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsigndocumentEditEzsignsignaturesV1Response
 * Response for PUT /1/object/ezsigndocument/{pkiEzsigndocumentID}/editEzsignsignatures
 * @export
 */
export type EzsigndocumentEditEzsignsignaturesV1Response = CommonResponse & EzsigndocumentEditEzsignsignaturesV1ResponseAllOf;


/**
 * @export 
 * A EzsigndocumentEditEzsignsignaturesV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigndocumentEditEzsignsignaturesV1Response
 */
export class DefaultObjectEzsigndocumentEditEzsignsignaturesV1Response extends DefaultObject {
   mPayload:Partial<EzsigndocumentEditEzsignsignaturesV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}



/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
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
import { EzsignfolderGetEzsigndocumentsV1ResponseAllOf } from './ezsignfolder-get-ezsigndocuments-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderGetEzsigndocumentsV1ResponseMPayload } from './ezsignfolder-get-ezsigndocuments-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsignfolderGetEzsigndocumentsV1Response
 * Response for GET /1/object/ezsignfolder/{pkiEzsignfolder}/getEzsigndocuments
 * @export
 */
export type EzsignfolderGetEzsigndocumentsV1Response = CommonResponse & EzsignfolderGetEzsigndocumentsV1ResponseAllOf;


/**
 * @export 
 * A EzsignfolderGetEzsigndocumentsV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignfolderGetEzsigndocumentsV1Response
 */
export class DefaultObjectEzsignfolderGetEzsigndocumentsV1Response extends DefaultObject {
   mPayload:Partial<EzsignfolderGetEzsigndocumentsV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}



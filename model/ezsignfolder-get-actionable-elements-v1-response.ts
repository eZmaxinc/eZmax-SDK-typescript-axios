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
import { EzsignfolderGetActionableElementsV1ResponseAllOf } from './ezsignfolder-get-actionable-elements-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderGetActionableElementsV1ResponseMPayload } from './ezsignfolder-get-actionable-elements-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsignfolderGetActionableElementsV1Response
 * Response for GET /1/object/ezsignfolder/{pkiEzsignfolderID}/getActionableElements
 * @export
 */
export type EzsignfolderGetActionableElementsV1Response = CommonResponse & EzsignfolderGetActionableElementsV1ResponseAllOf;


/**
 * @export 
 * A EzsignfolderGetActionableElementsV1Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignfolderGetActionableElementsV1Response
 */
export class DefaultObjectEzsignfolderGetActionableElementsV1Response extends DefaultObject {
   mPayload:Partial<EzsignfolderGetActionableElementsV1ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}



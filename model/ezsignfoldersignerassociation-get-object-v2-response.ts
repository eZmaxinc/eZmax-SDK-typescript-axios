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
import { EzsignfoldersignerassociationGetObjectV2ResponseAllOf } from './ezsignfoldersignerassociation-get-object-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationGetObjectV2ResponseMPayload } from './ezsignfoldersignerassociation-get-object-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsignfoldersignerassociationGetObjectV2Response
 * Response for GET /2/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}
 * @export
 */
export type EzsignfoldersignerassociationGetObjectV2Response = CommonResponse & EzsignfoldersignerassociationGetObjectV2ResponseAllOf;


/**
 * @export 
 * A EzsignfoldersignerassociationGetObjectV2Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignfoldersignerassociationGetObjectV2Response
 */
export class DefaultObjectEzsignfoldersignerassociationGetObjectV2Response extends DefaultObject {
   mPayload:Partial<EzsignfoldersignerassociationGetObjectV2ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}



/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
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
import { EzsignfoldertypeGetAutocompleteV2ResponseAllOf } from './ezsignfoldertype-get-autocomplete-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldertypeGetAutocompleteV2ResponseMPayload } from './ezsignfoldertype-get-autocomplete-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsignfoldertypeGetAutocompleteV2Response
 * Response for GET /2/object/ezsignfoldertype/getAutocomplete
 * @export
 */
export type EzsignfoldertypeGetAutocompleteV2Response = CommonResponse & EzsignfoldertypeGetAutocompleteV2ResponseAllOf;


/**
 * @export 
 * A EzsignfoldertypeGetAutocompleteV2Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignfoldertypeGetAutocompleteV2Response
 */
export class DefaultObjectEzsignfoldertypeGetAutocompleteV2Response extends DefaultObject {
   mPayload:Partial<EzsignfoldertypeGetAutocompleteV2ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}



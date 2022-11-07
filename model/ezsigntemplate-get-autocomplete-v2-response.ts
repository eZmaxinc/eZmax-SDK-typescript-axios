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
import { EzsigntemplateGetAutocompleteV2ResponseAllOf } from './ezsigntemplate-get-autocomplete-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateGetAutocompleteV2ResponseMPayload } from './ezsigntemplate-get-autocomplete-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplateGetAutocompleteV2Response
 * Response for GET /2/object/ezsigntemplate/getAutocomplete
 * @export
 */
export type EzsigntemplateGetAutocompleteV2Response = CommonResponse & EzsigntemplateGetAutocompleteV2ResponseAllOf;


/**
 * @export 
 * A EzsigntemplateGetAutocompleteV2Response Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplateGetAutocompleteV2Response
 */
export class DefaultObjectEzsigntemplateGetAutocompleteV2Response extends DefaultObject {
   mPayload:Partial<EzsigntemplateGetAutocompleteV2ResponseMPayload> = {}
   objDebugPayload?:Partial<CommonResponseObjDebugPayload> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}



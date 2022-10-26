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
import { EzsignSuggestTemplatesV1ResponseMPayload } from './ezsign-suggest-templates-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignSuggestTemplatesV1ResponseAllOf
 */
export interface EzsignSuggestTemplatesV1ResponseAllOf {
    /**
     * 
     * @type {EzsignSuggestTemplatesV1ResponseMPayload}
     * @memberof EzsignSuggestTemplatesV1ResponseAllOf
     */
    'mPayload': EzsignSuggestTemplatesV1ResponseMPayload;
}
/**
 * A EzsignSuggestTemplatesV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignSuggestTemplatesV1ResponseAllOf
 */
export class DefaultObjectEzsignSuggestTemplatesV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignSuggestTemplatesV1ResponseMPayload> = {}
}



/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateResponseCompound } from './ezsigntemplate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackageResponseCompound } from './ezsigntemplatepackage-response-compound';

import { DefaultObject } from '../base'

/**
 * Payload for GET /1/module/ezsign/suggestTemplates
 * @export
 * @interface EzsignSuggestTemplatesV1ResponseMPayload
 */
export interface EzsignSuggestTemplatesV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsigntemplateResponseCompound>}
     * @memberof EzsignSuggestTemplatesV1ResponseMPayload
     */
    'a_objEzsigntemplate': Array<EzsigntemplateResponseCompound>;
    /**
     * 
     * @type {Array<EzsigntemplatepackageResponseCompound>}
     * @memberof EzsignSuggestTemplatesV1ResponseMPayload
     */
    'a_objEzsigntemplatepackage': Array<EzsigntemplatepackageResponseCompound>;
}
/**
 * A EzsignSuggestTemplatesV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignSuggestTemplatesV1ResponseMPayload
 */
export class DefaultObjectEzsignSuggestTemplatesV1ResponseMPayload extends DefaultObject {
   a_objEzsigntemplate:Array<EzsigntemplateResponseCompound> = []
   a_objEzsigntemplatepackage:Array<EzsigntemplatepackageResponseCompound> = []
}



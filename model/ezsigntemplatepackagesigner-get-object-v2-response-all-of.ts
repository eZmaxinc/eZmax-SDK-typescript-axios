/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagesignerGetObjectV2ResponseMPayload } from './ezsigntemplatepackagesigner-get-object-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplatepackagesignerGetObjectV2ResponseAllOf
 */
export interface EzsigntemplatepackagesignerGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatepackagesignerGetObjectV2ResponseMPayload}
     * @memberof EzsigntemplatepackagesignerGetObjectV2ResponseAllOf
     */
    'mPayload': EzsigntemplatepackagesignerGetObjectV2ResponseMPayload;
}
/**
 * A EzsigntemplatepackagesignerGetObjectV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackagesignerGetObjectV2ResponseAllOf
 */
export class DefaultObjectEzsigntemplatepackagesignerGetObjectV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigntemplatepackagesignerGetObjectV2ResponseMPayload> = {}
}



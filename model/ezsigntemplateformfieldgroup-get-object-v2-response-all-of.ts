/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldgroupGetObjectV2ResponseMPayload } from './ezsigntemplateformfieldgroup-get-object-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplateformfieldgroupGetObjectV2ResponseAllOf
 */
export interface EzsigntemplateformfieldgroupGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplateformfieldgroupGetObjectV2ResponseMPayload}
     * @memberof EzsigntemplateformfieldgroupGetObjectV2ResponseAllOf
     */
    'mPayload': EzsigntemplateformfieldgroupGetObjectV2ResponseMPayload;
}
/**
 * A EzsigntemplateformfieldgroupGetObjectV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplateformfieldgroupGetObjectV2ResponseAllOf
 */
export class DefaultObjectEzsigntemplateformfieldgroupGetObjectV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigntemplateformfieldgroupGetObjectV2ResponseMPayload> = {}
}



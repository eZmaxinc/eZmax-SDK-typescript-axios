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
import { EzmaxinvoicingcommissionResponseCompound } from './ezmaxinvoicingcommission-response-compound';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzmaxinvoicingsummaryglobalResponseCompoundAllOf
 */
export interface EzmaxinvoicingsummaryglobalResponseCompoundAllOf {
    /**
     * 
     * @type {Array<EzmaxinvoicingcommissionResponseCompound>}
     * @memberof EzmaxinvoicingsummaryglobalResponseCompoundAllOf
     */
    'a_objEzmaxinvoicingcommission'?: Array<EzmaxinvoicingcommissionResponseCompound>;
}
/**
 * A EzmaxinvoicingsummaryglobalResponseCompoundAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzmaxinvoicingsummaryglobalResponseCompoundAllOf
 */
export class DefaultObjectEzmaxinvoicingsummaryglobalResponseCompoundAllOf extends DefaultObject {
   a_objEzmaxinvoicingcommission?:Array<EzmaxinvoicingcommissionResponseCompound> = undefined
}



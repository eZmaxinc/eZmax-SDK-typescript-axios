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



import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignfoldertypeRequestCompoundAllOf
 */
export interface EzsignfoldertypeRequestCompoundAllOf {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfoldertypeRequestCompoundAllOf
     */
    'a_fkiUserIDSigned'?: Array<number>;
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfoldertypeRequestCompoundAllOf
     */
    'a_fkiUserIDSummary'?: Array<number>;
}
/**
 * A EzsignfoldertypeRequestCompoundAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfoldertypeRequestCompoundAllOf
 */
export class DefaultObjectEzsignfoldertypeRequestCompoundAllOf extends DefaultObject {
   a_fkiUserIDSigned?:Array<number> = undefined
   a_fkiUserIDSummary?:Array<number> = undefined
}



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



import { DefaultObject } from '../base'

/**
 * An Ezsigntemplatedocument Object
 * @export
 * @interface EzsigntemplatedocumentRequestPatch
 */
export interface EzsigntemplatedocumentRequestPatch {
    /**
     * The name of the Ezsigntemplatedocument.
     * @type {string}
     * @memberof EzsigntemplatedocumentRequestPatch
     */
    'sEzsigntemplatedocumentName'?: string;
}
/**
 * A EzsigntemplatedocumentRequestPatch Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatedocumentRequestPatch
 */
export class DefaultObjectEzsigntemplatedocumentRequestPatch extends DefaultObject {
   sEzsigntemplatedocumentName?:string = undefined
}



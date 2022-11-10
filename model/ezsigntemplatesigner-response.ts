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
 * A Ezsigntemplatesigner Object
 * @export
 * @interface EzsigntemplatesignerResponse
 */
export interface EzsigntemplatesignerResponse {
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatesignerResponse
     */
    'pkiEzsigntemplatesignerID': number;
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplatesignerResponse
     */
    'fkiEzsigntemplateID': number;
    /**
     * The description of the Ezsigntemplatesigner
     * @type {string}
     * @memberof EzsigntemplatesignerResponse
     */
    'sEzsigntemplatesignerDescription': string;
}
/**
 * A EzsigntemplatesignerResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatesignerResponse
 */
export class DefaultObjectEzsigntemplatesignerResponse extends DefaultObject {
   pkiEzsigntemplatesignerID:number = 0
   fkiEzsigntemplateID:number = 0
   sEzsigntemplatesignerDescription:string = ''
}



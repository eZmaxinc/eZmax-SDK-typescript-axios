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
 * A Ezsigntemplatesigner Object
 * @export
 * @interface EzsigntemplatesignerRequest
 */
export interface EzsigntemplatesignerRequest {
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatesignerRequest
     */
    'pkiEzsigntemplatesignerID'?: number;
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplatesignerRequest
     */
    'fkiEzsigntemplateID': number;
    /**
     * The description of the Ezsigntemplatesigner
     * @type {string}
     * @memberof EzsigntemplatesignerRequest
     */
    'sEzsigntemplatesignerDescription': string;
}
/**
 * A EzsigntemplatesignerRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatesignerRequest
 */
export class DefaultObjectEzsigntemplatesignerRequest extends DefaultObject {
   pkiEzsigntemplatesignerID?:number = undefined
   fkiEzsigntemplateID:number = 0
   sEzsigntemplatesignerDescription:string = ''
}



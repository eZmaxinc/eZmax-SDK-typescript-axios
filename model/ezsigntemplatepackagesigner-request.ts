/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatepackagesignerMapping } from './field-eezsigntemplatepackagesigner-mapping';

/**
 * A Ezsigntemplatepackagesigner Object
 * @export
 * @interface EzsigntemplatepackagesignerRequest
 */
export interface EzsigntemplatepackagesignerRequest {
    /**
     * The unique ID of the Ezsigntemplatepackagesigner
     * @type {number}
     * @memberof EzsigntemplatepackagesignerRequest
     */
    /*'pkiEzsigntemplatepackagesignerID'?: number;*/
    'pkiEzsigntemplatepackagesignerID'?: number;
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepackagesignerRequest
     */
    /*'fkiEzsigntemplatepackageID': number;*/
    'fkiEzsigntemplatepackageID': number;
    /**
     * The unique ID of the Ezdoctemplatedocument
     * @type {number}
     * @memberof EzsigntemplatepackagesignerRequest
     */
    /*'fkiEzdoctemplatedocumentID'?: number;*/
    'fkiEzdoctemplatedocumentID'?: number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof EzsigntemplatepackagesignerRequest
     */
    /*'fkiUserID'?: number;*/
    'fkiUserID'?: number;
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof EzsigntemplatepackagesignerRequest
     */
    /*'fkiUsergroupID'?: number;*/
    'fkiUsergroupID'?: number;
    /**
     * If this flag is true. The signatory will receive a copy of every signed Ezsigndocument even if it ain\'t required to sign the document.
     * @type {boolean}
     * @memberof EzsigntemplatepackagesignerRequest
     */
    /*'bEzsigntemplatepackagesignerReceivecopy'?: boolean;*/
    'bEzsigntemplatepackagesignerReceivecopy'?: boolean;
    /**
     * 
     * @type {FieldEEzsigntemplatepackagesignerMapping}
     * @memberof EzsigntemplatepackagesignerRequest
     */
    /*'eEzsigntemplatepackagesignerMapping'?: FieldEEzsigntemplatepackagesignerMapping;*/
    'eEzsigntemplatepackagesignerMapping'?: FieldEEzsigntemplatepackagesignerMapping;
    /**
     * The description of the Ezsigntemplatepackagesigner
     * @type {string}
     * @memberof EzsigntemplatepackagesignerRequest
     */
    /*'sEzsigntemplatepackagesignerDescription': string;*/
    'sEzsigntemplatepackagesignerDescription': string;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackagesignerRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignerRequest
 */
export class DataObjectEzsigntemplatepackagesignerRequest {
   pkiEzsigntemplatepackagesignerID?:number = undefined
   fkiEzsigntemplatepackageID:number = 0
   fkiEzdoctemplatedocumentID?:number = undefined
   fkiUserID?:number = undefined
   fkiUsergroupID?:number = undefined
   bEzsigntemplatepackagesignerReceivecopy?:boolean = undefined
   eEzsigntemplatepackagesignerMapping?:FieldEEzsigntemplatepackagesignerMapping = undefined
   sEzsigntemplatepackagesignerDescription:string = ''
}

/**
 * @export 
 * A EzsigntemplatepackagesignerRequest Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignerRequest
 */
export class ValidationObjectEzsigntemplatepackagesignerRequest {
   pkiEzsigntemplatepackagesignerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigntemplatepackageID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzdoctemplatedocumentID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiUsergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   bEzsigntemplatepackagesignerReceivecopy = {
      type: 'boolean',
      required: false
   }
   eEzsigntemplatepackagesignerMapping = {
      type: 'enum',
      allowableValues: ['Manual','Creator','User','Usergroup'],
      required: false
   }
   sEzsigntemplatepackagesignerDescription = {
      type: 'string',
      required: true
   }
} 



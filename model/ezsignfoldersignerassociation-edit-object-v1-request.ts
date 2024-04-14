/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationRequestCompound } from './ezsignfoldersignerassociation-request-compound';

/**
 * Request for PUT /1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}
 * @export
 * @interface EzsignfoldersignerassociationEditObjectV1Request
 */
export interface EzsignfoldersignerassociationEditObjectV1Request {
    /**
     * 
     * @type {EzsignfoldersignerassociationRequestCompound}
     * @memberof EzsignfoldersignerassociationEditObjectV1Request
     */
    /*'objEzsignfoldersignerassociation': EzsignfoldersignerassociationRequestCompound;*/
    'objEzsignfoldersignerassociation': EzsignfoldersignerassociationRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfoldersignerassociationRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignfoldersignerassociationRequestCompound } from './'

/**
 * @export 
 * A EzsignfoldersignerassociationEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationEditObjectV1Request
 */
export class DataObjectEzsignfoldersignerassociationEditObjectV1Request {
   objEzsignfoldersignerassociation:EzsignfoldersignerassociationRequestCompound = new DataObjectEzsignfoldersignerassociationRequestCompound()
}

/**
 * @export 
 * A EzsignfoldersignerassociationEditObjectV1Request Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationEditObjectV1Request
 */
export class ValidationObjectEzsignfoldersignerassociationEditObjectV1Request {
   objEzsignfoldersignerassociation = new ValidationObjectEzsignfoldersignerassociationRequestCompound()
} 



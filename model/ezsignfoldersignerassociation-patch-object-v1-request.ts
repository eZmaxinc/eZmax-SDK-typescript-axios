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
import type { EzsignfoldersignerassociationRequestPatch } from './ezsignfoldersignerassociation-request-patch';

/**
 * Request for PATCH /1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}
 * @export
 * @interface EzsignfoldersignerassociationPatchObjectV1Request
 */
export interface EzsignfoldersignerassociationPatchObjectV1Request {
    /**
     * 
     * @type {EzsignfoldersignerassociationRequestPatch}
     * @memberof EzsignfoldersignerassociationPatchObjectV1Request
     */
    /*'objEzsignfoldersignerassociation': EzsignfoldersignerassociationRequestPatch;*/
    'objEzsignfoldersignerassociation': EzsignfoldersignerassociationRequestPatch;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfoldersignerassociationRequestPatch } from './'
// @ts-ignore
import { ValidationObjectEzsignfoldersignerassociationRequestPatch } from './'

/**
 * @export 
 * A EzsignfoldersignerassociationPatchObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationPatchObjectV1Request
 */
export class DataObjectEzsignfoldersignerassociationPatchObjectV1Request {
   objEzsignfoldersignerassociation:EzsignfoldersignerassociationRequestPatch = new DataObjectEzsignfoldersignerassociationRequestPatch()
}

/**
 * @export 
 * A EzsignfoldersignerassociationPatchObjectV1Request Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationPatchObjectV1Request
 */
export class ValidationObjectEzsignfoldersignerassociationPatchObjectV1Request {
   objEzsignfoldersignerassociation = new ValidationObjectEzsignfoldersignerassociationRequestPatch()
} 



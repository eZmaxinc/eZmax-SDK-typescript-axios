/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { EzsignfoldersignerassociationRequest } from './ezsignfoldersignerassociation-request';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignfoldersignerassociationRequestCompound } from './ezsignfoldersignerassociation-request-compound';

/**
 * Request for POST /1/object/ezsignfoldersignerassociation
 * @export
 * @interface EzsignfoldersignerassociationCreateObjectV1Request
 */
export interface EzsignfoldersignerassociationCreateObjectV1Request {
    /**
     * 
     * @type {EzsignfoldersignerassociationRequest}
     * @memberof EzsignfoldersignerassociationCreateObjectV1Request
     */
    /*'objEzsignfoldersignerassociation'?: EzsignfoldersignerassociationRequest;*/
    'objEzsignfoldersignerassociation'?: EzsignfoldersignerassociationRequest;
    /**
     * 
     * @type {EzsignfoldersignerassociationRequestCompound}
     * @memberof EzsignfoldersignerassociationCreateObjectV1Request
     */
    /*'objEzsignfoldersignerassociationCompound'?: EzsignfoldersignerassociationRequestCompound;*/
    'objEzsignfoldersignerassociationCompound'?: EzsignfoldersignerassociationRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfoldersignerassociationRequest } from './'
// @ts-ignore
import { DataObjectEzsignfoldersignerassociationRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignfoldersignerassociationRequest } from './'
// @ts-ignore
import { ValidationObjectEzsignfoldersignerassociationRequestCompound } from './'

/**
 * @export 
 * A EzsignfoldersignerassociationCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationCreateObjectV1Request
 */
export class DataObjectEzsignfoldersignerassociationCreateObjectV1Request {
   objEzsignfoldersignerassociation?:EzsignfoldersignerassociationRequest = undefined
   objEzsignfoldersignerassociationCompound?:EzsignfoldersignerassociationRequestCompound = undefined
}

/**
 * @export 
 * A EzsignfoldersignerassociationCreateObjectV1Request Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationCreateObjectV1Request
 */
export class ValidationObjectEzsignfoldersignerassociationCreateObjectV1Request {
   objEzsignfoldersignerassociation = new ValidationObjectEzsignfoldersignerassociationRequest()
   objEzsignfoldersignerassociationCompound = new ValidationObjectEzsignfoldersignerassociationRequestCompound()
} 



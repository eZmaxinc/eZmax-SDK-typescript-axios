/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.6
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsignfoldersignerassociationRequest } from './ezsignfoldersignerassociation-request';
import { EzsignfoldersignerassociationRequestCompound } from './ezsignfoldersignerassociation-request-compound';

/**
 * Request for the /1/object/ezsignfoldersignerassociation/createObject API Request
 * @export
 * @interface EzsignfoldersignerassociationCreateObjectV1Request
 */
export interface EzsignfoldersignerassociationCreateObjectV1Request {
    /**
     * 
     * @type {EzsignfoldersignerassociationRequest}
     * @memberof EzsignfoldersignerassociationCreateObjectV1Request
     */
    'objEzsignfoldersignerassociation'?: EzsignfoldersignerassociationRequest;
    /**
     * 
     * @type {EzsignfoldersignerassociationRequestCompound}
     * @memberof EzsignfoldersignerassociationCreateObjectV1Request
     */
    'objEzsignfoldersignerassociationCompound'?: EzsignfoldersignerassociationRequestCompound;
}

